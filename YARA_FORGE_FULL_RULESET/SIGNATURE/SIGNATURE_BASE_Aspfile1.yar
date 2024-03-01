import "pe"

rule SIGNATURE_BASE_Aspfile1
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file aspfile1.asp"
		author = "Florian Roth (Nextron Systems)"
		id = "1b66dec0-22c8-5937-a0b2-22cbc68241ef"
		date = "2014-11-23"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L1615-L1633"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "77b1e3a6e8f67bd6d16b7ace73dca383725ac0af"
		logic_hash = "4968e44f807f8ffface65e21fd8684ccfaee281b4da10f5110482c3f26ccac26"
		score = 60
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "' -- check for a command that we have posted -- '" fullword ascii
		$s1 = "szTempFile = \"C:\\\" & oFileSys.GetTempName( )" fullword ascii
		$s5 = "<meta http-equiv=\"Content-Type\" content=\"text/html; charset=gb2312\"><BODY>" fullword ascii
		$s6 = "<input type=text name=\".CMD\" size=45 value=\"<%= szCMD %>\">" fullword ascii
		$s8 = "Call oScript.Run (\"cmd.exe /c \" & szCMD & \" > \" & szTempFile, 0, True)" fullword ascii
		$s15 = "szCMD = Request.Form(\".CMD\")" fullword ascii

	condition:
		3 of them
}
