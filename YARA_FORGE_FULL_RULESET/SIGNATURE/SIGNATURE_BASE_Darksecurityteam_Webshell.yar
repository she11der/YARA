rule SIGNATURE_BASE_Darksecurityteam_Webshell
{
	meta:
		description = "Dark Security Team Webshell"
		author = "Florian Roth (Nextron Systems)"
		id = "78dcd62f-9215-5571-a5ef-5f811ce9672f"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L5525-L5537"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "f1c95b13a71ca3629a0bb79601fcacf57cdfcf768806a71b26f2448f8c1d5d24"
		logic_hash = "0c58ed8845cb04d785322b280647d424e1028a3be7e92b2493fd907fae36b16d"
		score = 50
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "form method=post><input type=hidden name=\"\"#\"\" value=Execute(Session(\"\"#\"\"))><input name=thePath value=\"\"\"&HtmlEncode(Server.MapPath(\".\"))&" ascii

	condition:
		1 of them
}
