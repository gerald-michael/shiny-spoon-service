use neon::prelude::*;
use inline_python;
use std::collections::HashMap;
pub fn binwalk_signature_scan(mut cx: FunctionContext) -> JsResult<JsArray> {
    let arg0: Handle<JsString> = cx.argument::<JsString>(0)?;
    let file = arg0.value(&mut cx);
    let c = inline_python::Context::new();
    c.run(
        inline_python::python!{
            import binwalk
            results = list()
            try:
                for module in binwalk.scan('file, signature=True, quiet=True, verbose=True):    
                    for result in module.results:
                        item = {"module_name": module.name,"file_name":result.file.name,"offset":str(result.offset),"description":result.description, "valid":str(result.valid)}
                        results.append(item);
            except binwalk.ModuleException as e:
                pass
        }
    );
    let binwalk_python_result: Vec<HashMap<String, String>> = c.get("results");
    let result = JsArray::new(&mut cx, binwalk_python_result.len() as u32);
    for (i, item) in binwalk_python_result.iter().enumerate() {
        let result_item = JsObject::new(&mut cx);
        let description = cx.string(item["description"].clone());
        let module_name = cx.string(item["module_name"].clone());
        let file_name = cx.string(item["file_name"].clone());
        let offset = cx.number(item["offset"].clone().parse::<u32>().unwrap());
        let valid = cx.boolean(item["valid"].clone().to_lowercase().parse().unwrap());
        result_item.set(&mut cx, "description", description).ok();
        result_item.set(&mut cx, "module_name", module_name).ok();
        result_item.set(&mut cx, "file_name", file_name).ok();
        result_item.set(&mut cx, "offset", offset).ok();
        result_item.set(&mut cx, "valid", valid).ok();
        result.set(&mut cx, i as u32, result_item).ok();
    }
    Ok(result)
}
pub fn binwalk_signature_extract(mut cx: FunctionContext) -> JsResult<JsArray> {
    let arg0: Handle<JsString> = cx.argument::<JsString>(0)?;
    let file = arg0.value(&mut cx);
    let c = inline_python::Context::new();
    c.run(
        inline_python::python!{
            import binwalk
            results_list = list()
            for module in binwalk.scan('file, signature=True, quiet=True, extract=True, directory="working-directory"):
                for result in module.results:
                    if result.file.path in module.extractor.output:
                        if result.offset in module.extractor.output[result.file.path].extracted:
                            item = {"module_name": module.name, "description":result.description, "offset": str(result.offset), "valid": str(result.valid), "extract": str(result.extract), "files":str(module.extractor.output[result.file.path].extracted[result.offset].files), "file_path": result.file.path}
                            results_list.append(item);
        }
    );
    let binwalk_python_result: Vec<HashMap<String, String>> = c.get("results_list");
    let result = JsArray::new(&mut cx, binwalk_python_result.len() as u32);
    for (i, item) in binwalk_python_result.iter().enumerate() {
        let result_item = JsObject::new(&mut cx);
        let description = cx.string(item["description"].clone());
        let module_name = cx.string(item["module_name"].clone());
        let offset = cx.number(item["offset"].clone().parse::<u32>().unwrap());
        let valid = cx.boolean(item["valid"].clone().to_lowercase().parse().unwrap());
        let extract = cx.boolean(item["extract"].clone().to_lowercase().parse().unwrap());
        let file_path = cx.string(item["file_path"].clone());
        let files = cx.string(item["files"].clone());
        result_item.set(&mut cx, "description", description).ok();
        result_item.set(&mut cx, "module_name", module_name).ok();
        result_item.set(&mut cx, "offset", offset).ok();
        result_item.set(&mut cx, "valid", valid).ok();
        result_item.set(&mut cx, "extract", extract).ok();
        result_item.set(&mut cx, "file_path", file_path).ok();
        result_item.set(&mut cx, "files", files).ok();
        result.set(&mut cx, i as u32, result_item).ok();
    }
    Ok(result)
}