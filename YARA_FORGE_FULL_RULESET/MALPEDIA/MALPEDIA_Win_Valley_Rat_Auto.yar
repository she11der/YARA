rule MALPEDIA_Win_Valley_Rat_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "5aadade8-2e86-5c22-9399-653890e95f9a"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.valley_rat"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.valley_rat_auto.yar#L1-L134"
		license_url = "N/A"
		logic_hash = "788630470fd0066c9dad5026f208a936da1b0fab9009cb8b3a3ebf9a9cd14823"
		score = 60
		quality = 45
		tags = "FILE"
		version = "1"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"

	strings:
		$sequence_0 = { 8b4910 e8???????? 2500020000 33d2 0bc2 7506 32c0 }
		$sequence_1 = { e8???????? 50 8d4708 50 e8???????? 8bbdf0efffff 83c414 }
		$sequence_2 = { 8bf0 83c404 85f6 742f e8???????? 84c0 ba???????? }
		$sequence_3 = { 50 e8???????? 8b5654 33c9 8b4508 83c408 894d08 }
		$sequence_4 = { 8d04dd00000000 50 e8???????? 8bf0 83c404 85f6 7447 }
		$sequence_5 = { 8bc2 c1e81f 03c2 8d0c40 8b07 8d04c8 894704 }
		$sequence_6 = { 8b55f4 4f 75ce 8b4df8 8b7d08 8b5510 3bca }
		$sequence_7 = { 8b36 c6043e00 5f 5e 5d c3 55 }
		$sequence_8 = { eb64 33c0 668945e4 e8???????? ff75dc 8b7b04 8d45e3 }
		$sequence_9 = { c745fc00000000 53 8bce e8???????? 8b06 83f801 741e }

	condition:
		7 of them and filesize <2256896
}
