rule CAPE_Agenttesla___FILE
{
	meta:
		description = "AgentTesla Payload"
		author = "kevoreilly"
		id = "f7b930f1-cecb-5d80-809b-9503f282247a"
		date = "2023-10-31"
		modified = "2023-10-31"
		reference = "https://github.com/kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/5db57762ada4ddb5b47cdb2c13150917f53241c0/data/yara/CAPE/AgentTesla.yar#L19-L41"
		license_url = "https://github.com/kevoreilly/CAPEv2/blob/5db57762ada4ddb5b47cdb2c13150917f53241c0/LICENSE"
		logic_hash = "1bf9b26c4cf87e674ddffabe40aba5a45499c6a04d4ff3e43c3cda4cbcb4d188"
		score = 75
		quality = 70
		tags = "FILE"
		cape_type = "AgentTesla Payload"

	strings:
		$string1 = "smtp" wide
		$string2 = "appdata" wide
		$string3 = "76487-337-8429955-22614" wide
		$string4 = "yyyy-MM-dd HH:mm:ss" wide
		$string6 = "webpanel" wide
		$string7 = "<br>UserName&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;:" wide
		$string8 = "<br>IP Address&nbsp;&nbsp;:" wide
		$agt1 = "IELibrary.dll" ascii
		$agt2 = "C:\\Users\\Admin\\Desktop\\IELibrary\\IELibrary\\obj\\Debug\\IELibrary.pdb" ascii
		$agt3 = "GetSavedPasswords" ascii
		$agt4 = "GetSavedCookies" ascii

	condition:
		uint16(0)==0x5A4D and ( all of ($string*) or 3 of ($agt*))
}