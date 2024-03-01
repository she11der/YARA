rule SIGNATURE_BASE_Webshell_Gfs_Sh_R57Shell_R57Shell127_Sniper_SA_Xxx
{
	meta:
		description = "Web Shell"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2014-01-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L2721-L2746"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "24d93f9ae5e174873a32abdf8dca6c00f03cbb4c5e2ad531ac7fa34f8fc90794"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash0 = "a2516ac6ee41a7cf931cbaef1134a9e4"
		hash1 = "ef43fef943e9df90ddb6257950b3538f"
		hash2 = "ae025c886fbe7f9ed159f49593674832"
		hash3 = "911195a9b7c010f61b66439d9048f400"
		hash4 = "697dae78c040150daff7db751fc0c03c"
		hash5 = "513b7be8bd0595c377283a7c87b44b2e"
		hash6 = "1d912c55b96e2efe8ca873d6040e3b30"
		hash7 = "e5b2131dd1db0dbdb43b53c5ce99016a"
		hash8 = "4108f28a9792b50d95f95b9e5314fa1e"
		hash9 = "41af6fd253648885c7ad2ed524e0692d"
		hash10 = "6fcc283470465eed4870bcc3e2d7f14d"

	strings:
		$s0 = "kVycm9yOiAkIVxuIik7DQpjb25uZWN0KFNPQ0tFVCwgJHBhZGRyKSB8fCBkaWUoIkVycm9yOiAkIVxuI"
		$s11 = "Aoc3RydWN0IHNvY2thZGRyICopICZzaW4sIHNpemVvZihzdHJ1Y3Qgc29ja2FkZHIpKSk8MCkgew0KIC"

	condition:
		all of them
}
