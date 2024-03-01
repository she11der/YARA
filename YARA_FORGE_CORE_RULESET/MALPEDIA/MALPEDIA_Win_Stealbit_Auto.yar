rule MALPEDIA_Win_Stealbit_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "ba610849-1495-5151-b945-327f0dc5f838"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.stealbit"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.stealbit_auto.yar#L1-L129"
		license_url = "N/A"
		logic_hash = "0ba0bc4f1da3f2dc67b8b88d21908b92c199e11ae8a3f814064895150fd93270"
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
		$sequence_0 = { 8b4e30 e8???????? 8b4e30 e8???????? 83663000 8d562c }
		$sequence_1 = { 8d8580fbffff 50 e8???????? 8bc8 e8???????? ffd0 8bd8 }
		$sequence_2 = { 8bfa 8bd9 e8???????? 8bc8 e8???????? ffd0 8bf0 }
		$sequence_3 = { e8???????? 8bc8 e8???????? ffd0 6a02 68bf000000 53 }
		$sequence_4 = { c786a802000000000000 8d7e50 33db 8b4620 }
		$sequence_5 = { 6a6f 66898546ffffff 33c0 66898548ffffff 58 6a63 668985d2fcffff }
		$sequence_6 = { 66899570feffff 66899574feffff 5a 6a6d 58 6a69 66898500feffff }
		$sequence_7 = { 6689859afeffff 33c0 668955de 5a 6a61 6689bd86feffff }
		$sequence_8 = { 8945f8 e8???????? 03c0 8bce 8bd0 e8???????? 6a0c }
		$sequence_9 = { e8???????? 8bc8 e8???????? 3d15cffdb1 740b 46 3bf7 }

	condition:
		7 of them and filesize <131072
}
