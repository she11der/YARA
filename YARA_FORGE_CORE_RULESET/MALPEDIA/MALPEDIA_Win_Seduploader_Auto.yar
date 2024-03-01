rule MALPEDIA_Win_Seduploader_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "7f16d7a9-71b0-5c84-ab55-9cb76a2d5976"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.seduploader"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.seduploader_auto.yar#L1-L113"
		license_url = "N/A"
		logic_hash = "59b0ef9c5ade0664bc2e5b83dd5075b45d913aac7ac67fc4cf5358fb404425b7"
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
		$sequence_0 = { 50 ff7630 e8???????? 83c40c 3b4508 }
		$sequence_1 = { c6411001 c3 55 8bec }
		$sequence_2 = { 8b4510 83c6fe 8930 8d4601 }
		$sequence_3 = { 8b4510 83c6fe 8930 8d4601 50 e8???????? }
		$sequence_4 = { 5e c3 55 8bec e8???????? 8b4d0c }
		$sequence_5 = { 8b4510 83c6fe 8930 8d4601 50 }
		$sequence_6 = { e8???????? 8b4510 83c6fe 8930 }
		$sequence_7 = { ff763c e8???????? 83c40c 3b4508 }
		$sequence_8 = { ff7630 e8???????? 83c40c 3b4508 }
		$sequence_9 = { 50 e8???????? 8b4510 83c6fe 8930 8d4601 50 }

	condition:
		7 of them and filesize <401408
}
