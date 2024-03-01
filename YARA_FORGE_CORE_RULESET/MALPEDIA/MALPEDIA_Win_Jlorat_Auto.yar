rule MALPEDIA_Win_Jlorat_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "eb5a0545-ab37-5e70-b9eb-6c48eb9adb8a"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.jlorat"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.jlorat_auto.yar#L1-L134"
		license_url = "N/A"
		logic_hash = "c96d7ee2744d61897b682d97d67d56d29e38731c8c93cf3d00f8d6450ca3d2bf"
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
		$sequence_0 = { e8???????? 83ec10 89c1 83c101 83d200 89542450 31c0 }
		$sequence_1 = { f20f114620 c7464001000000 89e0 8d5620 895004 8908 e8???????? }
		$sequence_2 = { f20f1086d8020000 f20f108ee0020000 f20f118e28030000 f20f118620030000 f20f108630030000 f20f118648030000 f20f108620030000 }
		$sequence_3 = { f6861618000001 0f85c0160000 e9???????? 8b4510 8b08 89e0 894804 }
		$sequence_4 = { eb00 e9???????? 8b559c 8b7580 8b7d84 8b5da4 8b4d88 }
		$sequence_5 = { e8???????? 8945c8 eb00 8b4dc4 8b45c8 c645e300 8945cc }
		$sequence_6 = { c745f0ffffffff 89e0 8d4dd8 8908 e8???????? 8b45c8 8b4de8 }
		$sequence_7 = { f30f118424d8000000 eb43 8b4c2448 8b54244c 89e0 895004 8908 }
		$sequence_8 = { e8???????? 894644 eb00 8b4e44 c601ff c64101ff c64102ff }
		$sequence_9 = { eb09 8b4df4 83c101 894df4 837df40a 7302 ebef }

	condition:
		7 of them and filesize <10952704
}
