rule MALPEDIA_Win_Medusalocker_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "ffdd3261-a5ad-520b-a2bf-3c67ba3f2e25"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.medusalocker"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.medusalocker_auto.yar#L1-L127"
		license_url = "N/A"
		logic_hash = "1d388adf94671d416a3d4bdcd878fd62d77b06e7650d468b56f2c1b04655aed4"
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
		$sequence_0 = { e8???????? 8945e8 eb07 c745e800000000 8b4de8 894de4 c645fc02 }
		$sequence_1 = { 8b4dd4 e8???????? 83c048 50 8d55d8 }
		$sequence_2 = { e8???????? 33c0 8845bb c745c488020000 6888020000 e8???????? 83c404 }
		$sequence_3 = { 83c404 8b08 51 e8???????? 83c410 }
		$sequence_4 = { 8845d7 8b4d08 e8???????? 0fb6c8 85c9 0f85f6000000 8b5508 }
		$sequence_5 = { 8d45e8 50 8b4d0c 51 e8???????? 83c404 50 }
		$sequence_6 = { 33c0 8945e8 668945ec b902000000 6bd100 668b450c }
		$sequence_7 = { 894508 8b4d08 3b4d0c 7427 8b5508 }
		$sequence_8 = { 8965d8 8b45e4 83c00c 50 e8???????? e8???????? 8b4de4 }
		$sequence_9 = { 8b55e0 52 6a01 8b4df0 e8???????? c645fc03 8d8d38ffffff }

	condition:
		7 of them and filesize <1433600
}
