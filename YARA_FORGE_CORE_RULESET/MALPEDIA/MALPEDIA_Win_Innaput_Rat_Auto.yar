rule MALPEDIA_Win_Innaput_Rat_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "bdbf07bd-d4a4-5362-b354-c606ef8af022"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.innaput_rat"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.innaput_rat_auto.yar#L1-L115"
		license_url = "N/A"
		logic_hash = "f6067a2a0e56ef408d96b72de49c1461531d24eb998121258442401a90d43684"
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
		$sequence_0 = { e8???????? 59 85c0 7427 ffb720060000 }
		$sequence_1 = { ffd7 8b4510 898618060000 8b4514 8b00 }
		$sequence_2 = { 8b06 894710 ff7604 035e08 ff5708 56 ff5708 }
		$sequence_3 = { 8d7710 eb02 8b36 391e 75fa 6a0c }
		$sequence_4 = { 8945fc ff15???????? 33db 395f10 }
		$sequence_5 = { ff15???????? ffb718060000 ff15???????? 85c0 }
		$sequence_6 = { 8b460c 83f8ff 7404 3bc3 751b }
		$sequence_7 = { eb02 8b36 391e 75fa 6a0c ff5704 59 }
		$sequence_8 = { 83f8ff 7404 3bc3 751b }
		$sequence_9 = { b001 ebd3 55 8bec }

	condition:
		7 of them and filesize <73728
}
