rule MALPEDIA_Win_Glupteba_Auto___FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "09a70f19-6d2a-5533-851a-d46346a3f052"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.glupteba"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.glupteba_auto.yar#L1-L163"
		license_url = "N/A"
		logic_hash = "f2320a7d413271b6097cf4accf3d3e4465e91ebbc62274538ef55443d4833776"
		score = 75
		quality = 75
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
		$sequence_0 = { 33c8 c1e102 33c8 03c9 }
		$sequence_1 = { ff75dc ff7508 ff75e2 e8???????? 83c410 ff35???????? ff15???????? }
		$sequence_2 = { 50 8d85fcf7ffff 50 56 e8???????? 68e8030000 8d85fcf7ffff }
		$sequence_3 = { 59 7e17 83c0fc 33c9 85c0 7e0e }
		$sequence_4 = { 334e04 8b75d0 33cf 8b7ddc c1ef08 c1ee10 }
		$sequence_5 = { 85c0 0f8435010000 807df473 7550 0fb745f7 50 }
		$sequence_6 = { 0f8f9c010000 894df8 ff7518 53 53 e8???????? }
		$sequence_7 = { 46 8975f8 83f810 7cd9 8d48f0 f7d9 1bc9 }
		$sequence_8 = { 0101 03d3 8b4620 8bcb }
		$sequence_9 = { 00cd 3e46 005e3e 46 }
		$sequence_10 = { 0107 eb4d 8b02 89442418 }
		$sequence_11 = { 00f1 3d46005e3e 46 00cd }
		$sequence_12 = { 0012 3f 46 008bff558bec }
		$sequence_13 = { 0106 830702 392e 75a0 }
		$sequence_14 = { 005e3e 46 00ff 3e46 }
		$sequence_15 = { 00ff 3e46 0012 3f }

	condition:
		7 of them and filesize <1417216
}