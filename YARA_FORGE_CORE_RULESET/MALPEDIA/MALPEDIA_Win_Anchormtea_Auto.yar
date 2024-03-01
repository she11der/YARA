rule MALPEDIA_Win_Anchormtea_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "1f1be8a6-a512-5951-b4a5-8a59e9561b7d"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.anchormtea"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.anchormtea_auto.yar#L1-L156"
		license_url = "N/A"
		logic_hash = "36b7e20db6ab94edc928176040f9980c01a0a26295c603a430e96744ecfde5c2"
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
		$sequence_0 = { e9???????? f7d8 1bc0 83e002 }
		$sequence_1 = { 33c0 6689047e eb14 51 }
		$sequence_2 = { 83f81f 0f87f3080000 52 51 e8???????? }
		$sequence_3 = { 7409 488bcf ff15???????? 33f6 4c8b7c2448 4c8b642460 }
		$sequence_4 = { 488905???????? 488d055b7e0200 488905???????? 488d05897d0200 48890d???????? 48890d???????? }
		$sequence_5 = { 899d1cffffff ffd7 50 ffd6 }
		$sequence_6 = { 8b9580f7ffff 89856cf7ffff 8b85acf7ffff 2bc7 898d5cf7ffff 89bd64f7ffff }
		$sequence_7 = { 4983ff10 4c0f43f7 4c8b6c2470 4983fd0b 725f 4f8d242e }
		$sequence_8 = { 51 57 8d4dd8 e8???????? 33d2 895588 90 }
		$sequence_9 = { 4883c0f8 4883f81f 772e e8???????? 8bc6 }
		$sequence_10 = { 488d9510020000 488bcb ff15???????? 413b7624 }
		$sequence_11 = { 4a8d3c39 488bc6 482bc2 4869d88c090000 }
		$sequence_12 = { 33ff 488945d0 488d45e0 4533c9 4889442448 4533c0 }
		$sequence_13 = { 740e 6a40 68???????? 68???????? ffd7 8d45f8 }
		$sequence_14 = { 7514 3b8598fdffff 1bc0 238598fdffff }

	condition:
		7 of them and filesize <839680
}
