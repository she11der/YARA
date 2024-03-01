rule MALPEDIA_Win_Zenar_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "4a5b8e75-0846-5f97-8625-2c49ccc878e4"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.zenar"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.zenar_auto.yar#L1-L128"
		license_url = "N/A"
		logic_hash = "aaf8e2aaae847a92d9529fc5af1d76e9bd4aae4fdb4d807ed83b4a0145bc159f"
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
		$sequence_0 = { 85c0 7409 83c024 50 8b08 ff5108 8b4df4 }
		$sequence_1 = { 8bf1 8d8e80020000 e8???????? 8d8e68020000 e8???????? 8bce 5e }
		$sequence_2 = { 8bc7 8bcf 83e03f c1f906 6bf038 03348d98ae4300 }
		$sequence_3 = { 8d8d70ffffff c645fc03 e8???????? 84c0 7406 8ac3 }
		$sequence_4 = { 8bfe 83e03f c1ff06 6bd838 8b04bd98ae4300 f644032801 7444 }
		$sequence_5 = { 55 8bec 0fb701 83ec10 83e811 741a 83e801 }
		$sequence_6 = { 8d4d0c ff7514 8b7d08 8945f8 897314 }
		$sequence_7 = { 8b4dfc 0f95c0 890a c9 c20c00 55 8bec }
		$sequence_8 = { 837d0c04 0f85e3000000 8d4634 50 8d4dc8 e8???????? }
		$sequence_9 = { eb07 8b4584 8930 33db 8d4dd4 e8???????? }

	condition:
		7 of them and filesize <519168
}
