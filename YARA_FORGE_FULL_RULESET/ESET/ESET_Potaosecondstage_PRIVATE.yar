private rule ESET_Potaosecondstage_PRIVATE
{
	meta:
		description = "No description has been set in the source file - ESET"
		author = "ESET TI"
		id = "c1baace9-f481-533a-aa85-df5ba14069f2"
		date = "2015-07-30"
		modified = "2015-07-30"
		reference = "https://github.com/eset/malware-ioc"
		source_url = "https://github.com/eset/malware-ioc/blob/0f1104d8a7b3b77b66257d22588a281d8e93ca4b/potao/PotaoNew.yara#L81-L95"
		license_url = "https://github.com/eset/malware-ioc/blob/0f1104d8a7b3b77b66257d22588a281d8e93ca4b/LICENSE"
		logic_hash = "55f9fc2da09aa9c2e76725985c836f7b8ba5e0b69a9327fb911e8265b340b88c"
		score = 75
		quality = 28
		tags = ""

	strings:
		$mz = { 4d 5a }
		$binary1 = {51 7A BB 85 [10-180] E8 47 D2 A8}
		$binary2 = {5F 21 63 DD [10-30] EC FD 33 02}
		$binary3 = {CA 77 67 57 [10-30] BA 08 20 7A}
		$str1 = "?AVCrypt32Import@@"
		$str2 = "%.5llx"

	condition:
		($mz at 0) and any of ($binary*) and any of ($str*)
}
