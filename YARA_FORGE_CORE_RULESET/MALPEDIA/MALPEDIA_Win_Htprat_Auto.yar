rule MALPEDIA_Win_Htprat_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "67b2e8d9-4f49-5cf6-8afe-0a9a5bcb5d69"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.htprat"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.htprat_auto.yar#L1-L127"
		license_url = "N/A"
		logic_hash = "15d5d8ea42e22569434bb0dbf96f0b13036ea7676d82ad93d8f718afb8dd6a66"
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
		$sequence_0 = { 8b8568efffff 03c6 3b8558efffff 7667 8b8394000000 898560efffff 8b8558efffff }
		$sequence_1 = { 8bc7 897dcc e8???????? 8b5dc8 3b5f04 740e }
		$sequence_2 = { 8d4c2418 c68424e800000003 e8???????? 8b00 3bc3 7504 32db }
		$sequence_3 = { 33d2 f3a6 6aff 58 7404 1bd2 1bd0 }
		$sequence_4 = { 46 56 8d8d00ffffff e8???????? 53 56 }
		$sequence_5 = { 85c0 750c e8???????? a3???????? eb13 53 }
		$sequence_6 = { 8b00 8d8d38efffff 51 8d8d08efffff 51 50 ff33 }
		$sequence_7 = { 894584 99 f77d8c 8b4590 8a0402 8b5594 }
		$sequence_8 = { 83c604 3b7734 75ec eb31 83f805 }
		$sequence_9 = { 8d410c 8bcb e8???????? 84c0 0f84d2000000 8b5d0c }

	condition:
		7 of them and filesize <278528
}
