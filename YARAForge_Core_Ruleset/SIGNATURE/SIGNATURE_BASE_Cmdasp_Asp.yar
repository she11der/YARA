rule SIGNATURE_BASE_Cmdasp_Asp
{
	meta:
		description = "Semi-Auto-generated  - file CmdAsp.asp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "79e0ba85-ed4b-5909-a2fd-9b4125598078"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L4131-L4144"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "64f24f09ec6efaa904e2492dffc518b9"
		logic_hash = "95dc25ecd47b43edbd7e7e36966377aa09da769aff2bc1c33a7df87989611bfa"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "CmdAsp.asp"
		$s1 = "Set oFileSys = Server.CreateObject(\"Scripting.FileSystemObject\")" fullword
		$s2 = "-- Use a poor man's pipe ... a temp file --"
		$s3 = "maceo @ dogmile.com"

	condition:
		2 of them
}