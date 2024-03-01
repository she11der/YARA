rule SIGNATURE_BASE_Webshell_Imhapftp_2
{
	meta:
		description = "Web Shell - file iMHaPFtp.php"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2014-01-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L80-L94"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "12911b73bc6a5d313b494102abcf5c57"
		logic_hash = "9099504870c1e466808060f11aea38472832846d24e3c84fdd69b7d26bfed69d"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s8 = "if ($l) echo '<a href=\"' . $self . '?action=permission&amp;file=' . urlencode($"
		$s9 = "return base64_decode('R0lGODlhEQANAJEDAMwAAP///5mZmf///yH5BAHoAwMALAAAAAARAA0AAA"

	condition:
		1 of them
}
