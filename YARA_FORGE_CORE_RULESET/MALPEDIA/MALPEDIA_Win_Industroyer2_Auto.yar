rule MALPEDIA_Win_Industroyer2_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "01c28e59-8cb1-5bf1-9de6-64ce0dd77d4a"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.industroyer2"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.industroyer2_auto.yar#L1-L130"
		license_url = "N/A"
		logic_hash = "bbf01a0f560944dbb85cdfc8fdeff74a884348b77c6b1a1a74790ea421be78c4"
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
		$sequence_0 = { 732c 837df800 7426 8b45fc 8b4df4 8b1481 89559c }
		$sequence_1 = { 89480c 8b55fc 8b451c 894210 694d18a0860100 034d1c }
		$sequence_2 = { eb07 c745d000000000 8b4508 8a4dd0 888845000100 }
		$sequence_3 = { 8b4d08 e8???????? 8945fc 68???????? 8b4508 50 }
		$sequence_4 = { 885103 8b45fc 8b4804 8b551c 8b8238000100 894104 8b4dfc }
		$sequence_5 = { c1e200 8b45fc 8b4d08 8a1411 885005 b801000000 d1e0 }
		$sequence_6 = { 8b4df0 51 ff15???????? 85c0 7406 c645ff01 eb04 }
		$sequence_7 = { c6400c00 8b4dfc c641140a 6a04 8b55fc 83c210 52 }
		$sequence_8 = { 837df800 742c 8b55fc 8b45f4 8b0c90 898d78ffffff 8b9578ffffff }
		$sequence_9 = { 8b45fc 50 e8???????? 0fb6c8 85c9 7444 68???????? }

	condition:
		7 of them and filesize <100352
}