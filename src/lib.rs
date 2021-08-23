use std::error::Error; use std::sync::Mutex;
use neon::prelude::*;
use openpgp_card_pcsc::PcscClient;
use openpgp_card::card_app::CardApp;
use openpgp_card::{Hash, KeyType, PublicKeyMaterial};

macro_rules! throw {
    ($cx:expr, $res:expr) => {
        match $res {
            Ok(v) => v,
            Err(err) => $cx.throw_error(err.to_string())?,
        }
    };
}

struct MyCardApp(Mutex<CardApp>);

impl Finalize for MyCardApp {}

fn smartcard_open(mut cx: FunctionContext) -> JsResult<JsBox<MyCardApp>> {
    let id = cx.argument::<JsString>(0)?.value(&mut cx);
    let client = throw!(cx, PcscClient::open_by_ident(&id));
    let client = MyCardApp(Mutex::new(CardApp::new(client)));
    Ok(cx.boxed(client))
}

fn smartcard_get_pub_key(mut cx: FunctionContext) -> JsResult<JsString> {
    let app = cx.argument::<JsBox<MyCardApp>>(0)?;
    let pubkey = throw!(cx, app.0.lock().unwrap().get_pub_key(KeyType::Authentication));

    let ssh_pubkey = throw!(cx, pubkey_to_ssh(pubkey));
    Ok(cx.string(ssh_pubkey))
}

fn pubkey_to_ssh(pubkey: openpgp_card::PublicKeyMaterial) -> Result<String, Box<dyn Error + Send + Sync>> {
    match pubkey {
        // SSH-RSA
        PublicKeyMaterial::R(rsa) => {
            let mut data = Vec::new();
            data.extend(&u32::to_be_bytes("ssh-rsa".len() as _));
            data.extend("ssh-rsa".as_bytes());
            data.extend(&u32::to_be_bytes(rsa.n.len() as _));
            data.extend(rsa.n);
            data.extend(&u32::to_be_bytes(rsa.v.len() as _));
            data.extend(rsa.v);
            Ok(format!("ssh-rsa {}", base64::encode(data)))
        },
        //PublicKeyMaterial::E(ec) => {
        //    todo!()
        //},
        _ => Err("Unknown key type".into()),
    }
}

fn smartcard_signature_for_hash(mut cx: FunctionContext) -> JsResult<JsBuffer> {
    let app = cx.argument::<JsBox<MyCardApp>>(0)?;
    let hash = cx.argument::<JsString>(1)?.value(&mut cx);
    let data = {
        let data = cx.argument::<JsBuffer>(2)?;
        let lock = cx.lock();
        let r = data.borrow(&lock);
        r.as_slice().to_vec()
    };
    let hash = match hash.as_str() {
        "sha256" => {
            let mut hash_arr = [0; 32];
            if data.len() != 32 {
                return cx.throw_error(format!("Invalid data len for hash type {}", hash));
            }
            hash_arr.copy_from_slice(&data);
            Hash::SHA256(hash_arr)
        },
        _ => cx.throw_error(format!("Invalid hash type {}", hash))?,
    };
    let sig = app.0.lock().unwrap().signature_for_hash(hash)
        .or_else(|err| cx.throw_error(format!("Failed to sign data: {}", err)))?;

    let mut out_buf = cx.buffer(sig.len() as _)?;

    {
        let lock = cx.lock();
        out_buf.borrow_mut(&lock).as_mut_slice().copy_from_slice(&sig);
    }

    Ok(out_buf)
}

fn smartcard_list_ids(mut cx: FunctionContext) -> JsResult<JsArray> {
    let cards = throw!(cx, PcscClient::list_cards());
    let out_arr = JsArray::new(&mut cx, cards.len() as u32);

    for (i, card) in cards.into_iter().enumerate() {
        let client = MyCardApp(Mutex::new(CardApp::new(card)));
        let client = cx.boxed(client);
        out_arr.set(&mut cx, i as u32, client)?;
    }

    Ok(out_arr)
}

#[neon::main]
fn main(mut cx: ModuleContext) -> NeonResult<()> {
    cx.export_function("smartcard_open", smartcard_open)?;
    cx.export_function("smartcard_get_pub_key", smartcard_get_pub_key)?;
    cx.export_function("smartcard_signature_for_hash", smartcard_signature_for_hash)?;
    cx.export_function("smartcard_list_ids", smartcard_list_ids)?;
    Ok(())
}
