rule SIGNATURE_BASE_APT_MAL_LUA_Hunting_Lua_SEASPRAY_1
{
	meta:
		description = "Hunting rule looking for strings observed in SEASPRAY samples."
		author = "Mandiant"
		id = "8c744b85-b61e-56d0-8a9e-ae6a954e1b95"
		date = "2023-06-15"
		modified = "2023-12-05"
		reference = "https://www.mandiant.com/resources/blog/barracuda-esg-exploited-globally"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_barracuda_esg_unc4841_jun23.yar#L213-L228"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "35cf6faf442d325961935f660e2ab5a0"
		logic_hash = "856bfb47557b60f69aa1141477d6ce446ea13ebbe899022d7996ceef08bdefbb"
		score = 70
		quality = 85
		tags = ""

	strings:
		$str1 = "string.find(attachment:filename(),'obt075') ~= nil"
		$str2 = "os.execute('cp '..tostring(tmpfile)..' /tmp/'..attachment:filename())"
		$str3 = "os.execute('rverify'..' /tmp/'..attachment:filename())"

	condition:
		all of them
}
