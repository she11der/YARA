rule SIGNATURE_BASE_Warfiles_Cmd : FILE
{
	meta:
		description = "Laudanum Injector Tools - file cmd.jsp"
		author = "Florian Roth (Nextron Systems)"
		id = "f974255b-cfbe-57b0-af1f-eddb7f12f5ed"
		date = "2015-06-22"
		modified = "2023-12-05"
		reference = "http://laudanum.inguardians.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_laudanum_webshells.yar#L262-L278"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "3ae3d837e7b362de738cf7fad78eded0dccf601f"
		logic_hash = "64724b24d9f5b5d78e231ea8196abb609237cc430c49f6ceeb99c9684a904568"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "Process p = Runtime.getRuntime().exec(request.getParameter(\"cmd\"));" fullword ascii
		$s2 = "out.println(\"Command: \" + request.getParameter(\"cmd\") + \"<BR>\");" fullword ascii
		$s3 = "<FORM METHOD=\"GET\" NAME=\"myform\" ACTION=\"\">" fullword ascii
		$s4 = "String disr = dis.readLine();" fullword ascii

	condition:
		filesize <2KB and all of them
}
