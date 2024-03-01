rule SIGNATURE_BASE_Coinminer_Strings : SCRIPT HIGHVOL FILE
{
	meta:
		description = "Detects mining pool protocol string in Executable"
		author = "Florian Roth (Nextron Systems)"
		id = "ac045f83-5f32-57a9-8011-99a2658a0e05"
		date = "2018-01-04"
		modified = "2021-10-26"
		reference = "https://minergate.com/faq/what-pool-address"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/pua_cryptocoin_miner.yar#L2-L18"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "2d63bf90560c83ab6c09e0c82b6a6449bca6e7e7d0945d3782c2fa9a726b2ca1"
		score = 60
		quality = 85
		tags = "FILE"
		nodeepdive = 1

	strings:
		$sa1 = "stratum+tcp://" ascii
		$sa2 = "stratum+udp://" ascii
		$sb1 = "\"normalHashing\": true,"

	condition:
		filesize <3000KB and 1 of them
}
