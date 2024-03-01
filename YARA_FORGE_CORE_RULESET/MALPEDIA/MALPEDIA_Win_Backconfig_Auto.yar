rule MALPEDIA_Win_Backconfig_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "18fd149c-ad9b-5433-8651-ac1dcd92de05"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.backconfig"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.backconfig_auto.yar#L1-L127"
		license_url = "N/A"
		logic_hash = "dc29e43fa81d60d5f53e6f4d5e158937c417e8f12650929b20d71338a8cb5ead"
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
		$sequence_0 = { a1???????? 8b0d???????? 8b15???????? 8985f0feffff a1???????? 6a51 8985fcfeffff }
		$sequence_1 = { e8???????? 8b4de4 83c40c 6bc930 8975e0 8db1682a4100 }
		$sequence_2 = { 8a15???????? 8d8569ffffff 6a00 50 898d64ffffff 889568ffffff }
		$sequence_3 = { c1f805 8d1485c0504100 8b0a 83e61f c1e606 03ce }
		$sequence_4 = { 8bc3 c1f805 8d3c85c0504100 8bf3 83e61f c1e606 8b07 }
		$sequence_5 = { 8b0d???????? 8b15???????? 8985f0feffff a1???????? 6a51 8985fcfeffff 898df4feffff }
		$sequence_6 = { 8d8d2cfdffff 68???????? 51 e8???????? 83c414 68401f0000 }
		$sequence_7 = { 6a00 50 898d64ffffff 889568ffffff e8???????? }
		$sequence_8 = { 8bf1 83e61f 8d3c85c0504100 8b07 c1e606 f644300401 7436 }
		$sequence_9 = { 8bec 8b4508 56 8d34c550224100 833e00 7513 }

	condition:
		7 of them and filesize <217088
}
