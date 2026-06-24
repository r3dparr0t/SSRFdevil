use mlua::{Lua, Table};
use std::error::Error;

pub fn execute_lua_bypass(script_source: &str, entry_fn: &str, target_url: &str) -> Result<String, Box<dyn Error>> {
    let lua = Lua::new();

    // ۱. لود کردن و کامپایل کد لوآ
    lua.load(script_source).exec()?;

    // ۲. ساختن آبجکت ctx (Context) برای پاس دادن به ورودی تابع لوآ
    let ctx = lua.create_table()?;
    ctx.set("target", target_url)?;

    // ۳. پیدا کردن تابع اصلی (مثلاً bypass) در اسکریپت لوآ
    let func: mlua::Function = lua.globals().get(entry_fn)?;

    // ۴. صدا زدن تابع با ورودی ctx و گرفتن خروجی به صورت Table
    let result: Table = func.call(ctx)?;

    // ۵. استخراج فیلد url از جدول برگشتی لوآ
    let final_url: String = result.get("url")?;

    Ok(final_url)
}
