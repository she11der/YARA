rule ELASTIC_Windows_Vulndriver_Amifldrv_E387D5Ad : FILE
{
	meta:
		description = "Detects Windows Vulndriver Amifldrv (Windows.VulnDriver.Amifldrv)"
		author = "Elastic Security"
		id = "e387d5ad-fde8-401b-bdcf-044c4f7f5fbd"
		date = "2022-04-04"
		modified = "2022-04-04"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/84213d9b40fee553ea3065cb4bb057c7c1685b59/yara/rules/Windows_VulnDriver_Amifldrv.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/84213d9b40fee553ea3065cb4bb057c7c1685b59/LICENSE.txt"
		hash = "fda506e2aa85dc41a4cbc23d3ecc71ab34e06f1def736e58862dc449acbc2330"
		logic_hash = "14d75b5aff2c82d69b041c654cdc0840f6b6e37a197f5c0c1c2698c9e8eba3e2"
		score = 60
		quality = 55
		tags = "FILE"
		fingerprint = "03f898088f37f3c9991fb70d7fb8548908cfac4e03bb2bfe88b11a65157909a8"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$str1 = "\\amifldrv64.pdb"

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $str1
}
