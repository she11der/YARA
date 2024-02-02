rule SIGNATURE_BASE_APT_MAL_LUA_Hunting_SKIPJACK_1
{
	meta:
		description = "Hunting rule looking for strings observed in SKIPJACK installation script."
		author = "Mandiant"
		id = "0026375c-7f37-5ef9-bd55-5b9fc499e5d2"
		date = "2023-06-15"
		modified = "2023-12-05"
		reference = "https://www.mandiant.com/resources/blog/barracuda-esg-exploited-globally"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_barracuda_esg_unc4841_jun23.yar#L175-L193"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "e4e86c273a2b67a605f5d4686783e0cc"
		logic_hash = "8890cd9ab8190f12997e0653e43c89816df03c7bd41842e5ad21b1986819843e"
		score = 70
		quality = 85
		tags = ""

	strings:
		$str1 = "hdr:name() == 'Content-ID'" base64
		$str2 = "hdr:body() ~= nil" base64
		$str3 = "string.match(hdr:body(),\"^[%w%+/=\\r\\n]+$\")" base64
		$str4 = "openssl aes-256-cbc" base64
		$str5 = "mod_content.lua"
		$str6 = "#!/bin/sh"

	condition:
		all of them
}