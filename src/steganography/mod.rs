use neon::prelude::*;
mod white_character_steg;
use lsb_png_steganography;
use lsb_text_png_steganography;
pub fn white_space_steg_hide(mut cx: FunctionContext) -> JsResult<JsString> {
    let arg0: Handle<JsString> = cx.argument::<JsString>(0)?;
    let arg1: Handle<JsString> = cx.argument::<JsString>(1)?;
    let payload = arg0.value(&mut cx);
    let carrier = arg1.value(&mut cx);
    let output = white_character_steg::hider::interleave(payload, carrier);
    Ok(cx.string(output))
}
pub fn white_space_steg_reveal(mut cx: FunctionContext) -> JsResult<JsString> {
    let arg0: Handle<JsString> = cx.argument::<JsString>(0)?;
    let carrier = arg0.value(&mut cx);
    let hidden = white_character_steg::revealer::extract(carrier);
    Ok(cx.string(hidden))
}
pub fn png_steg_text_file_hide(mut cx: FunctionContext) -> JsResult<JsString> {
    let arg0: Handle<JsString> = cx.argument::<JsString>(0)?;
    let arg1: Handle<JsString> = cx.argument::<JsString>(1)?;
    let arg2: Handle<JsString> = cx.argument::<JsString>(2)?;
    let carrier = arg0.value(&mut cx);
    let payload_text = arg1.value(&mut cx);
    let output_png = arg2.value(&mut cx);
    let img = lsb_text_png_steganography::hide(&payload_text, &carrier);
    match img.save(output_png) {
        Ok(_) => Ok(cx.string("success")),
        Err(_) => Ok(cx.string("failed to save")),
    }
    // Ok(cx.string(hidden))
}
pub fn png_steg_text_file_reveal(mut cx: FunctionContext) -> JsResult<JsString> {
    let arg0: Handle<JsString> = cx.argument::<JsString>(0)?;
    let carrier = arg0.value(&mut cx);
    Ok(cx.string(lsb_text_png_steganography::reveal(&carrier)))
}
pub fn png_steg_png_file_hide(mut cx: FunctionContext) -> JsResult<JsString> {
    let arg0: Handle<JsString> = cx.argument::<JsString>(0)?;
    let arg1: Handle<JsString> = cx.argument::<JsString>(1)?;
    let arg2: Handle<JsString> = cx.argument::<JsString>(2)?;
    let carrier = arg0.value(&mut cx);
    let payload_text = arg1.value(&mut cx);
    let output_png = arg2.value(&mut cx);
    let img = lsb_png_steganography::hide(&payload_text, &carrier);
    match img.save(output_png) {
        Ok(_) => Ok(cx.string("success")),
        Err(_) => Ok(cx.string("failed to save")),
    }
    // Ok(cx.string(hidden))
}
pub fn png_steg_png_file_reveal(mut cx: FunctionContext) -> JsResult<JsString> {
    let arg0: Handle<JsString> = cx.argument::<JsString>(0)?;
    let arg1: Handle<JsString> = cx.argument::<JsString>(1)?;
    let carrier = arg0.value(&mut cx);
    let output_path = arg1.value(&mut cx);
    let img = lsb_png_steganography::reveal(&carrier);
    match img.save(output_path) {
        Ok(_) => Ok(cx.string("success")),
        Err(_) => Ok(cx.string("failed to save")),
    }
}
