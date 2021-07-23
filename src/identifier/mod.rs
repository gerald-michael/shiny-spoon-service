use hash_data;
use neon::prelude::*;
pub fn identify(mut cx: FunctionContext) -> JsResult<JsArray> {
    let arg0: Handle<JsString> = cx.argument::<JsString>(0)?;
    let str = arg0.value(&mut cx);
    let idenfied = hash_data::parse(&str);
    let js_array = JsArray::new(&mut cx, idenfied.len() as u32);
    for (i, obj) in idenfied.iter().enumerate() {
        let js_string = cx.string(obj);
        js_array.set(&mut cx, i as u32, js_string).unwrap();
    }
    Ok(js_array)
}