rule SIGNATURE_BASE_Getuserspns_VBS
{
	meta:
		description = "Auto-generated rule - file GetUserSPNs.vbs"
		author = "Florian Roth (Nextron Systems)"
		id = "5576c1b9-4670-52c5-b23c-64adcc8709de"
		date = "2016-05-21"
		modified = "2023-12-05"
		reference = "https://github.com/skelsec/PyKerberoast"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_kerberoast.yar#L8-L23"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "ece81cd717fed6ca1f9053384911fd59462b6f3b01210ceeb037ba3da2f7a318"
		score = 75
		quality = 60
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "8dcb568d475fd8a0557e70ca88a262b7c06d0f42835c855b52e059c0f5ce9237"

	strings:
		$s1 = "Wscript.Echo \"User Logon: \" & oRecordset.Fields(\"samAccountName\")" fullword ascii
		$s2 = "Wscript.Echo \" USAGE:        \" & WScript.ScriptName & \" SpnToFind [GC Servername or Forestname]\"" fullword ascii
		$s3 = "strADOQuery = \"<\" + strGCPath + \">;(&(!objectClass=computer)(servicePrincipalName=*));\" & _" fullword ascii

	condition:
		2 of them
}
