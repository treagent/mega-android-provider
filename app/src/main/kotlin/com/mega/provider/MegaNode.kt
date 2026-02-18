package com.mega.provider

data class MegaNode(
    val handle: String,
    val parentHandle: String,
    val name: String,
    val isFolder: Boolean,
    val size: Long,
    val modificationTime: Long
)
