rule SIGNATURE_BASE_Webshell_Acid_Fatalisticz_Fx_Fx_P0Ison_Sh3Ll_X0Rg_Byp4Ss_256 : FILE
{
	meta:
		description = "Detects Webshell"
		author = "Florian Roth (Nextron Systems)"
		id = "80f7d202-adb8-5d9c-b176-576e3b9553c1"
		date = "2016-01-11"
		modified = "2023-12-05"
		reference = "https://github.com/nikicat/web-malware-collection"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L9435-L9454"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "07cd255247c9a77b1c9b6049a2b96632252ea9572880b10991c6797c14a05d48"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "7a69466dbd18182ce7da5d9d1a9447228dcebd365e0fe855d0e02024f4117549"
		hash2 = "d0edca7539ef2d30f0b3189b21a779c95b5815c1637829b5594e2601e77cb4dc"
		hash3 = "65e7edf10ffb355bed81b7413c77d13d592f63d39e95948cdaea4ea0a376d791"
		hash4 = "ba87d26340f799e65c771ccb940081838afe318ecb20ee543f32d32db8533e7f"
		hash5 = "1fdf6e142135a34ae1caf1d84adf5e273b253ca46c409b2530ca06d65a55ecbd"

	strings:
		$s0 = "<form method=\"POST\"><input type=hidden name=act value=\"ls\">" fullword ascii
		$s2 = "foreach($quicklaunch2 as $item) {" fullword ascii

	condition:
		filesize <882KB and all of them
}
