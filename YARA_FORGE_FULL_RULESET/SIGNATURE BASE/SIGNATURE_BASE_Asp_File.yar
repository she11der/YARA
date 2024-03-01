rule SIGNATURE_BASE_Asp_File : FILE
{
	meta:
		description = "Laudanum Injector Tools - file file.asp"
		author = "Florian Roth (Nextron Systems)"
		id = "e2a80d1f-f2bb-573b-b68c-71e4dfa6e1fa"
		date = "2015-06-22"
		modified = "2023-12-05"
		reference = "http://laudanum.inguardians.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_laudanum_webshells.yar#L8-L26"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "ff5b1a9598735440bdbaa768b524c639e22f53c5"
		logic_hash = "9ec19a994571f4d1b40b6d6af3fb6eb4c5004a6439b99863b50dae0262677263"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "' *** Written by Tim Medin <tim@counterhack.com>" fullword ascii
		$s2 = "Response.BinaryWrite(stream.Read)" fullword ascii
		$s3 = "Response.Write(Response.Status & Request.ServerVariables(\"REMOTE_ADDR\"))" fullword ascii
		$s4 = "%><a href=\"<%=Request.ServerVariables(\"URL\")%>\">web root</a><br/><%" fullword ascii
		$s5 = "set folder = fso.GetFolder(path)" fullword ascii
		$s6 = "Set file = fso.GetFile(filepath)" fullword ascii

	condition:
		uint16(0)==0x253c and filesize <30KB and 5 of them
}
