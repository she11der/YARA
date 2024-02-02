rule SIGNATURE_BASE_KINS_Dropper
{
	meta:
		description = "Match protocol, process injects and windows exploit present in KINS dropper"
		author = "AlienVault Labs aortega@alienvault.com"
		id = "17e12685-aaad-5d83-949c-43d5aef1ef0d"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "http://goo.gl/arPhm3"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/crime_kins_dropper.yar#L1-L26"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "cdab93f823e13e0c3104de8e05cb1572f83fb5294f359698092d73fc7983955b"
		score = 75
		quality = 85
		tags = ""

	strings:
		$n1 = "tid=%d&ta=%s-%x" fullword
		$n2 = "fid=%d" fullword
		$n3 = "%[^.].%[^(](%[^)])" fullword
		$i0 = "%s [%s %d] 77 %s"
		$i01 = "Global\\%s%x"
		$i1 = "Inject::InjectProcessByName()"
		$i2 = "Inject::CopyImageToProcess()"
		$i3 = "Inject::InjectProcess()"
		$i4 = "Inject::InjectImageToProcess()"
		$i5 = "Drop::InjectStartThread()"
		$uac1 = "ExploitMS10_092"
		$uac2 = "\\globalroot\\systemroot\\system32\\tasks\\" ascii wide
		$uac3 = "<RunLevel>HighestAvailable</RunLevel>" ascii wide

	condition:
		2 of ($n*) and 2 of ($i*) and 2 of ($uac*)
}