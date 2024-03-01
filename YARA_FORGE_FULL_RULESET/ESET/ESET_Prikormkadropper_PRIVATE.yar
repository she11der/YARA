private rule ESET_Prikormkadropper_PRIVATE
{
	meta:
		description = "No description has been set in the source file - ESET"
		author = "ESET TI"
		id = "d333693d-5386-5c34-a1c1-7a17e5bde849"
		date = "2019-08-28"
		modified = "2019-08-28"
		reference = "https://github.com/eset/malware-ioc"
		source_url = "https://github.com/eset/malware-ioc/blob/0f1104d8a7b3b77b66257d22588a281d8e93ca4b/groundbait/prikormka.yar#L33-L51"
		license_url = "https://github.com/eset/malware-ioc/blob/0f1104d8a7b3b77b66257d22588a281d8e93ca4b/LICENSE"
		logic_hash = "cf524cdf4ffeb5c9280c5c8e7fca524c41e1ce4f9bc46b1fc8cb8b50ea68ec39"
		score = 75
		quality = 28
		tags = ""

	strings:
		$mz = { 4D 5A }
		$kd00 = "KDSTORAGE" wide
		$kd01 = "KDSTORAGE_64" wide
		$kd02 = "KDRUNDRV32" wide
		$kd03 = "KDRAR" wide
		$bin00 = {69 65 04 15 00 14 1E 4A 16 42 08 6C 21 61 24 0F}
		$bin01 = {76 6F 05 04 16 1B 0D 5E 0D 42 08 6C 20 45 18 16}
		$bin02 = {4D 00 4D 00 43 00 00 00 67 00 75 00 69 00 64 00 56 00 47 00 41 00 00 00 5F 00 73 00 76 00 67 00}
		$inj00 = "?AVCinj2008Dlg@@" ascii
		$inj01 = "?AVCinj2008App@@" ascii

	condition:
		($mz at 0) and (( any of ($bin*)) or (3 of ($kd*)) or ( all of ($inj*)))
}
