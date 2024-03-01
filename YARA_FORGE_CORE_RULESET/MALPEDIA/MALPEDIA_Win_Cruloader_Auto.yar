rule MALPEDIA_Win_Cruloader_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "975bd752-b718-50f1-9af8-cfa41728edc9"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.cruloader"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.cruloader_auto.yar#L1-L124"
		license_url = "N/A"
		logic_hash = "a1572c6250fefbf1b80a173c44c61e578e12fe07ff0f92d960b828b4e32b23d4"
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
		$sequence_0 = { 53 ff15???????? 6a04 6800100000 ff35???????? 6a00 }
		$sequence_1 = { 6bf638 8b0c8dd85e4100 80643128fd 5f 5e c9 c3 }
		$sequence_2 = { 0f1005???????? 50 0f1145e0 ff15???????? 33c9 90 8a540dd0 }
		$sequence_3 = { 3bf7 72e9 5f f7d0 5e 8be5 }
		$sequence_4 = { 88540dc0 41 3bc8 7ced }
		$sequence_5 = { 83c404 0f1000 6a00 0f1185ccfbffff ff15???????? }
		$sequence_6 = { 833d????????00 0f851c0e0000 8d0db02f4100 ba1b000000 e9???????? a900000080 7517 }
		$sequence_7 = { 7309 80341961 41 3bca 72f7 e8???????? 8d45ec }
		$sequence_8 = { 0f8c5cffffff c705????????01000000 8b7d08 83c8ff }
		$sequence_9 = { 0f8494010000 8bb5e4fcffff 8d45f4 50 ff7354 57 ff75e8 }

	condition:
		7 of them and filesize <196608
}
