rule MALPEDIA_Win_Risepro_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "aea6ceb4-8818-596f-b0ea-b016b3dee8c1"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.risepro"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.risepro_auto.yar#L1-L125"
		license_url = "N/A"
		logic_hash = "4bf4a4e2719baa2456fbc7c987c0d3507fd8f7c3c54ce53243c1cdc1f6723c61"
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
		$sequence_0 = { 0fb645ff 50 8b4de8 e8???????? 8b4dec 83c901 894dec }
		$sequence_1 = { e8???????? 8945c8 8d4d0c e8???????? 8945cc 8d45d7 50 }
		$sequence_2 = { 8bec 83ec0c 8955f8 894dfc 8b4dfc e8???????? 8bc8 }
		$sequence_3 = { 894214 8b4df8 e8???????? 8945d4 837de010 }
		$sequence_4 = { 8bcc 8965bc 8d552c 52 e8???????? 8945b8 c645fc04 }
		$sequence_5 = { 33c0 8885eafeffff 33c9 888de9feffff }
		$sequence_6 = { 6800000080 680000cf00 68???????? 68???????? 6800020000 ff15???????? 89859cfeffff }
		$sequence_7 = { 6886e4fa74 6829895415 e8???????? 8b4dfc 894108 89510c }
		$sequence_8 = { 33c5 8945ec 56 50 8d45f4 64a300000000 894da8 }
		$sequence_9 = { 85ff 780f 3b3d???????? 7307 }

	condition:
		7 of them and filesize <280576
}
