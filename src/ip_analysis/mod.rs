use neon::prelude::*;
mod banner_grabber;
mod port_scanner;
pub fn grab_banner(mut cx: FunctionContext) -> JsResult<JsObject> {
    let arg0: Handle<JsString> = cx.argument::<JsString>(0)?;
    let address = arg0.value(&mut cx);
    let result = JsObject::new(&mut cx);
    match banner_grabber::grab_banner(&address) {
        Ok(data) => {
            let data = cx.string(data);
            result.set(&mut cx, "data", data).ok();
        }
        Err(_) => {
            let error_message = cx.string("Something went wrong");
            result.set(&mut cx, "error", error_message).ok();
        }
    };
    Ok(result)
}

pub fn scan_port_addrs(mut cx: FunctionContext) -> JsResult<JsArray> {
    let arg0: Handle<JsArray> = cx.argument::<JsArray>(0)?;
    let arg1: Handle<JsArray> = cx.argument::<JsArray>(1)?;
    let vec1: Vec<Handle<JsValue>> = arg0.to_vec(&mut cx)?;
    let vec2: Vec<Handle<JsValue>> = arg1.to_vec(&mut cx)?;
    let mut addresses: Vec<String> = Vec::new();
    let mut ports: Vec<u16> = Vec::new();
    for address in vec1 {
        let value = address.clone();
        let new_value = value
            .downcast::<JsString, _>(&mut cx)
            .unwrap()
            .value(&mut cx);
        addresses.push(new_value);
    }
    for port in vec2 {
        let value = port.clone();
        let new_value = value
            .downcast::<JsNumber, _>(&mut cx)
            .unwrap()
            .value(&mut cx);
        ports.push(new_value as u16);
    }
    let result = port_scanner::scan_port_addrs(addresses, ports);
    let open_address_array = JsArray::new(&mut cx, result.len() as u32);
    for (i, open_adrr) in result.iter().enumerate() {
        let address = JsObject::new(&mut cx);
        let ip = cx.string(open_adrr.ip.clone());
        let port = cx.number(open_adrr.port);
        let x = port_scanner::get_services_tcp();
        let service_name = cx.string(x[&open_adrr.port].service_name.clone());
        let protocal = cx.string(x[&open_adrr.port].protocal.clone());
        let open_frequency = cx.number(x[&open_adrr.port].open_frequency.clone());
        let optional_comment = cx.string(x[&open_adrr.port].optional_comment.clone());
        address.set(&mut cx, "ip", ip).ok();
        address.set(&mut cx, "port", port).ok();
        address.set(&mut cx, "service_name", service_name).ok();
        address.set(&mut cx, "protocal", protocal).ok();
        address.set(&mut cx, "open_frequency", open_frequency).ok();
        address
            .set(&mut cx, "optional_comment", optional_comment)
            .ok();
        open_address_array.set(&mut cx, i as u32, address).ok();
    }
    Ok(open_address_array)
}
pub fn scan_port_addrs_range(mut cx: FunctionContext) -> JsResult<JsArray> {
    let arg0: Handle<JsArray> = cx.argument::<JsArray>(0)?;
    let arg1: Handle<JsNumber> = cx.argument::<JsNumber>(1)?;
    let arg2: Handle<JsNumber> = cx.argument::<JsNumber>(2)?;
    let vec1: Vec<Handle<JsValue>> = arg0.to_vec(&mut cx)?;
    let start = arg1.value(&mut cx) as u16;
    let stop = arg2.value(&mut cx) as u16;
    let mut addresses: Vec<String> = Vec::new();
    for address in vec1 {
        let value = address.clone();
        let new_value = value
            .downcast::<JsString, _>(&mut cx)
            .unwrap()
            .value(&mut cx);
        addresses.push(new_value);
    }
    let result = port_scanner::scan_port_addrs_range(addresses, start..stop);
    let open_address_array = JsArray::new(&mut cx, result.len() as u32);
    for (i, open_adrr) in result.iter().enumerate() {
        let address = JsObject::new(&mut cx);
        let ip = cx.string(open_adrr.ip.clone());
        let port = cx.number(open_adrr.port);
        let x = port_scanner::get_services_tcp();
        let service_name = cx.string(x[&open_adrr.port].service_name.clone());
        let protocal = cx.string(x[&open_adrr.port].protocal.clone());
        let open_frequency = cx.number(x[&open_adrr.port].open_frequency.clone());
        let optional_comment = cx.string(x[&open_adrr.port].optional_comment.clone());
        address.set(&mut cx, "ip", ip).ok();
        address.set(&mut cx, "port", port).ok();
        address.set(&mut cx, "service_name", service_name).ok();
        address.set(&mut cx, "protocal", protocal).ok();
        address.set(&mut cx, "open_frequency", open_frequency).ok();
        address
            .set(&mut cx, "optional_comment", optional_comment)
            .ok();
        open_address_array.set(&mut cx, i as u32, address).ok();
    }
    Ok(open_address_array)
}
