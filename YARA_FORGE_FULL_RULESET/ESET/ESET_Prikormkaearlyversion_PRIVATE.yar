private rule ESET_Prikormkaearlyversion_PRIVATE
{
	meta:
		description = "No description has been set in the source file - ESET"
		author = "ESET TI"
		id = "f10e6477-c4bb-50be-8827-66de35a9aea8"
		date = "2019-08-28"
		modified = "2019-08-28"
		reference = "https://github.com/eset/malware-ioc"
		source_url = "https://github.com/eset/malware-ioc/blob/0f1104d8a7b3b77b66257d22588a281d8e93ca4b/groundbait/prikormka.yar#L112-L128"
		license_url = "https://github.com/eset/malware-ioc/blob/0f1104d8a7b3b77b66257d22588a281d8e93ca4b/LICENSE"
		logic_hash = "681c7fb322953da162c10b76e453aa8ace6673720012383e3cd5528b59b42de3"
		score = 75
		quality = 28
		tags = ""

	strings:
		$mz = { 4D 5A }
		$str00 = "IntelRestore" ascii fullword
		$str01 = "Resent" wide fullword
		$str02 = "ocp8.1" wide fullword
		$str03 = "rsfvxd.dat" ascii fullword
		$str04 = "tsb386.dat" ascii fullword
		$str05 = "frmmlg.dat" ascii fullword
		$str06 = "smdhost.dll" ascii fullword
		$str07 = "KDLLCFX" wide fullword
		$str08 = "KDLLRUNDRV" wide fullword

	condition:
		($mz at 0) and (2 of ($str*))
}
