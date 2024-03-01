rule SIGNATURE_BASE_APT_MAL_LUA_Hunting_Lua_SKIPJACK_2
{
	meta:
		description = "Hunting rule looking for strings observed in SKIPJACK samples."
		author = "Mandiant"
		id = "e1eac294-fe60-5bb2-bae4-0f7bcbe6b1db"
		date = "2023-06-15"
		modified = "2023-12-05"
		reference = "https://www.mandiant.com/resources/blog/barracuda-esg-exploited-globally"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_barracuda_esg_unc4841_jun23.yar#L195-L212"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "87847445f9524671022d70f2a812728f"
		logic_hash = "093e8857c410bd30a076f87ef63d7e1e66f50e3dce75b4add67161782386ee24"
		score = 70
		quality = 85
		tags = ""

	strings:
		$str1 = "hdr:name() == 'Content-ID'"
		$str2 = "hdr:body() ~= nil"
		$str3 = "string.match(hdr:body(),\"^[%w%+/=\\r\\n]+$\")"
		$str4 = "openssl aes-256-cbc"
		$str5 = "| base64 -d| sh 2>"

	condition:
		all of them
}
