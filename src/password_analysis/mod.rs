use neon::prelude::*;
use zxcvbn::zxcvbn;
pub fn password_strength_estimator(mut cx: FunctionContext) -> JsResult<JsObject> {
    let arg0: Handle<JsString> = cx.argument::<JsString>(0)?;
    let arg1: Handle<JsArray> = cx.argument::<JsArray>(1)?;
    let password = arg0.value(&mut cx);
    let vec: Vec<Handle<JsValue>> = arg1.to_vec(&mut cx)?;
    let mut others: Vec<String> = Vec::new();
    for info in vec {
        let value = info.clone();
        let new_value = value
            .downcast::<JsString, _>(&mut cx)
            .unwrap()
            .value(&mut cx);
        others.push(new_value);
    }
    let mut other = [""; 5];
    for i in 0..5 {
        if i >= others.len() {
            break;
        }
        other[i] = match others.get(i) {
            Some(value) => value,
            None => "",
        };
    }
    let estimate = zxcvbn(&password, &other).unwrap();
    let js_object = JsObject::new(&mut cx);
    let strength = cx.number(estimate.score());
    let online_no_throttling_10_per_second = cx.string(
        estimate
            .crack_times()
            .online_no_throttling_10_per_second()
            .to_string(),
    );
    let offline_fast_hashing_1e10_per_second = cx.string(
        estimate
            .crack_times()
            .offline_fast_hashing_1e10_per_second()
            .to_string(),
    );
    let offline_slow_hashing_1e4_per_second = cx.string(
        estimate
            .crack_times()
            .offline_slow_hashing_1e4_per_second()
            .to_string(),
    );
    let online_throttling_100_per_hour = cx.string(
        estimate
            .crack_times()
            .online_throttling_100_per_hour()
            .to_string(),
    );
    let guesses = cx.number(estimate.guesses() as f64);
    js_object.set(&mut cx, "strength", strength).ok();
    js_object.set(&mut cx, "guesses", guesses).ok();
    js_object
        .set(
            &mut cx,
            "online_no_throttling_10_per_second",
            online_no_throttling_10_per_second,
        )
        .ok();
    js_object
        .set(
            &mut cx,
            "offline_fast_hashing_1e10_per_second",
            offline_fast_hashing_1e10_per_second,
        )
        .ok();
    js_object
        .set(
            &mut cx,
            "offline_slow_hashing_1e4_per_second",
            offline_slow_hashing_1e4_per_second,
        )
        .ok();
    js_object
        .set(
            &mut cx,
            "online_throttling_100_per_hour",
            online_throttling_100_per_hour,
        )
        .ok();
    match estimate.feedback() {
        Some(feedback) => {
            match feedback.warning() {
                Some(warning) => {
                    let message = cx.string(warning.to_string());
                    js_object.set(&mut cx, "warning", message).ok();
                }
                None => {
                    let message = cx.string("");
                    js_object.set(&mut cx, "warning", message).ok();
                }
            };
            let suggestions = feedback.suggestions();
            let js_array = JsArray::new(&mut cx, suggestions.len() as u32);
            for (i, suggestion) in suggestions.iter().enumerate() {
                let js_string = cx.string(suggestion.to_string());
                js_array.set(&mut cx, i as u32, js_string).unwrap();
            }
            js_object.set(&mut cx, "suggestions", js_array).ok();
        }
        None => {}
    };
    Ok(js_object)
}
