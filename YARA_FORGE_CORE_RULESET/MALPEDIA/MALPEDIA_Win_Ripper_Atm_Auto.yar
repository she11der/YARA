rule MALPEDIA_Win_Ripper_Atm_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "a163a628-88ff-5ee3-8ab0-3e7869e5ed11"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ripper_atm"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.ripper_atm_auto.yar#L1-L131"
		license_url = "N/A"
		logic_hash = "30a8a446c0211fbfa8563685de5143789e29b7c89e693b370c3a643209d252a9"
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
		$sequence_0 = { 8b7d08 2175fc 397714 7e2a ff770c 8b33 8bcb }
		$sequence_1 = { 0f434dd8 837dd408 8d5598 52 8d9550ffffff 52 }
		$sequence_2 = { 3938 8b45ec 7408 8b4de8 3b4810 7327 8b4e08 }
		$sequence_3 = { 6a0f 50 ff15???????? 85c0 7402 32c0 c20800 }
		$sequence_4 = { 8b02 6a04 8b4804 03ca e8???????? }
		$sequence_5 = { 6a1c e8???????? 59 85c0 7420 33c9 c7400410000000 }
		$sequence_6 = { c1f805 83e21f 8b0c85f0974400 c1e206 8a441124 3245fe 247f }
		$sequence_7 = { 51 8d55c8 8d4d8c e8???????? 83c410 84c0 7445 }
		$sequence_8 = { 8bf9 50 e8???????? ff7518 8d45ec ff7514 8bcf }
		$sequence_9 = { 03f0 8b442424 2bc1 99 f77c2418 47 3bf8 }

	condition:
		7 of them and filesize <724992
}
