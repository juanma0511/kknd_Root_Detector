package com.juanma0511.rootdetector.ui

import androidx.compose.animation.*
import androidx.compose.animation.core.*
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.luminance
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.juanma0511.rootdetector.MainViewModel
import com.juanma0511.rootdetector.model.*

// Detection palette (see design spec). Light mode uses the spec colors; dark
// mode brightens the deep maroon/green so they stay legible on #272727.
fun hardDetectionColor(isDark: Boolean): Color = if (isDark) Color(0xFFE5527A) else Color(0xFFA3122F)
fun warningColor(isDark: Boolean): Color = if (isDark) Color(0xFFF0C044) else Color(0xFFC68500)
fun passColor(isDark: Boolean): Color = if (isDark) Color(0xFF3FBE7C) else Color(0xFF157A3C)

@Composable
fun RootDetectorScreen(viewModel: MainViewModel) {
    val scanState by viewModel.scanState.collectAsState()
    val scanProgress by viewModel.scanProgress.collectAsState()
    val scanResult by viewModel.scanResult.collectAsState()
    var selectedSeverity by rememberSaveable { mutableStateOf<Severity?>(null) }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(start = 16.dp, end = 16.dp, top = 16.dp, bottom = 104.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item {
            StatusHeroCard(
                scanState = scanState,
                scanProgress = scanProgress,
                scanResult = scanResult,
                onScanClick = { viewModel.startScan() }
            )
        }

        if (scanState == ScanState.DONE && scanResult != null) {
            item {
                SummaryRow(
                    result = scanResult!!,
                    selectedSeverity = selectedSeverity,
                    onSeverityClick = { severity ->
                        selectedSeverity = if (selectedSeverity == severity) null else severity
                    }
                )
            }
        }

        if (scanState == ScanState.DONE && scanResult != null) {
            val filteredItems = scanResult!!.checks.filter { item ->
                selectedSeverity == null || item.severity == selectedSeverity
            }
            val grouped = filteredItems.sortedWith(
                compareByDescending<CheckResult> { it.detected }
                    .thenBy { it.severity.ordinal }
            )
            items(grouped) { item ->
                CheckResultCard(item)
            }
        }
    }
}

@Composable
fun StatusHeroCard(
    scanState: ScanState,
    scanProgress: Int,
    scanResult: ScanResult?,
    onScanClick: () -> Unit
) {
    val animatedProgress by animateFloatAsState(
        targetValue = scanProgress / 100f,
        animationSpec = tween(300),
        label = "progress"
    )

    val isDark = MaterialTheme.colorScheme.surface.luminance() < 0.5f
    val statusColor = when {
        scanResult == null -> MaterialTheme.colorScheme.primary
        scanResult.status == ScanStatus.ROOTED -> hardDetectionColor(isDark)
        scanResult.status == ScanStatus.SUSPICIOUS -> warningColor(isDark)
        scanResult.status == ScanStatus.INCOMPLETE -> MaterialTheme.colorScheme.error
        else -> passColor(isDark)
    }

    val containerColor = when {
        scanResult == null  -> if (isDark) Color(0xFF0D1B2E) else Color(0xFFDCE8FF)
        scanResult.status == ScanStatus.ROOTED -> if (isDark) Color(0xFF2E0A0A) else Color(0xFFFFDAD6)
        scanResult.status == ScanStatus.SUSPICIOUS -> if (isDark) Color(0xFF2A1A00) else Color(0xFFFFDBC8)
        scanResult.status == ScanStatus.INCOMPLETE -> MaterialTheme.colorScheme.errorContainer
        else -> if (isDark) Color(0xFF0A1F0A) else Color(0xFFE8F5E9)
    }

    val iconScale by animateFloatAsState(
        targetValue = if (scanState == ScanState.SCANNING) 0.9f else 1f,
        animationSpec = if (scanState == ScanState.SCANNING) {
            infiniteRepeatable(animation = tween(800), repeatMode = RepeatMode.Reverse)
        } else spring(),
        label = "scale"
    )

    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(28.dp),
        colors = CardDefaults.cardColors(containerColor = containerColor),
        elevation = CardDefaults.cardElevation(defaultElevation = 0.dp)
    ) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Box(
                contentAlignment = Alignment.Center,
                modifier = Modifier
                    .size(88.dp)
                    .scale(iconScale)
                    .clip(CircleShape)
                    .background(statusColor.copy(alpha = if (isDark) 0.24f else 0.12f))
            ) {
                Icon(
                    imageVector = when {
                        scanState == ScanState.SCANNING -> Icons.Outlined.Search
                        scanResult?.status == ScanStatus.ROOTED -> Icons.Filled.Warning
                        scanResult?.status == ScanStatus.SUSPICIOUS -> Icons.Filled.Info
                        scanResult?.status == ScanStatus.INCOMPLETE -> Icons.Filled.Error
                        scanResult != null -> Icons.Filled.CheckCircle
                        else -> Icons.Outlined.Shield
                    },
                    contentDescription = null,
                    tint = statusColor,
                    modifier = Modifier.size(48.dp)
                )
            }

            Spacer(Modifier.height(16.dp))

            Text(
                text = when {
                    scanState == ScanState.IDLE -> "Ready to Scan"
                    scanState == ScanState.SCANNING -> "Scanning..."
                    scanResult?.status == ScanStatus.ROOTED -> "Root Detected"
                    scanResult?.status == ScanStatus.SUSPICIOUS -> "Suspicious"
                    scanResult?.status == ScanStatus.INCOMPLETE -> "Scan Incomplete"
                    scanResult != null -> "Device Clean"
                    else -> "Ready to Scan"
                },
                style = MaterialTheme.typography.headlineSmall,
                fontWeight = FontWeight.Bold,
                color = statusColor
            )

            Text(
                text = when {
                    scanState == ScanState.IDLE -> "Tap below to run a full security analysis"
                    scanState == ScanState.SCANNING -> "Running $scanProgress% of checks..."
                    scanResult?.status == ScanStatus.ROOTED ->
                        "${scanResult.detectedCount} indicators found · ${scanResult.highRiskCount} high risk"
                    scanResult?.status == ScanStatus.SUSPICIOUS ->
                        "${scanResult.detectedCount} warning indicators found"
                    scanResult?.status == ScanStatus.INCOMPLETE ->
                        "${scanResult.summary.failedChecks} check(s) failed to complete"
                    scanResult != null -> "All ${scanResult.checks.size} checks completed without detections"
                    else -> ""
                },
                style = MaterialTheme.typography.bodyMedium,
                color = statusColor.copy(alpha = 0.8f),
                modifier = Modifier.padding(top = 4.dp)
            )

            Spacer(Modifier.height(20.dp))

            AnimatedContent(
                targetState = scanState,
                transitionSpec = { fadeIn(tween(300)) togetherWith fadeOut(tween(200)) },
                label = "action"
            ) { state ->
                when (state) {
                    ScanState.IDLE -> {
                        Button(
                            onClick = onScanClick,
                            modifier = Modifier.fillMaxWidth().height(52.dp),
                            shape = RoundedCornerShape(16.dp),
                            colors = ButtonDefaults.buttonColors(containerColor = statusColor)
                        ) {
                            Icon(
                                imageVector = Icons.Outlined.PlayArrow,
                                contentDescription = null,
                                modifier = Modifier.size(20.dp)
                            )
                            Spacer(Modifier.width(8.dp))
                            Text(
                                "Start Scan",
                                fontWeight = FontWeight.SemiBold,
                                fontSize = 16.sp
                            )
                        }
                    }
                    ScanState.DONE -> {
                        Button(
                            onClick = onScanClick,
                            modifier = Modifier.fillMaxWidth().height(52.dp),
                            shape = RoundedCornerShape(16.dp),
                            colors = ButtonDefaults.buttonColors(containerColor = statusColor)
                        ) {
                            Icon(
                                imageVector = Icons.Filled.Refresh,
                                contentDescription = null,
                                modifier = Modifier.size(20.dp)
                            )
                            Spacer(Modifier.width(8.dp))
                            Text(
                                "Scan Again",
                                fontWeight = FontWeight.SemiBold,
                                fontSize = 16.sp
                            )
                        }
                    }
                    ScanState.SCANNING -> {
                        Column(horizontalAlignment = Alignment.CenterHorizontally) {
                            LinearProgressIndicator(
                                progress = { animatedProgress },
                                modifier = Modifier.fillMaxWidth().height(8.dp).clip(CircleShape),
                                color = statusColor,
                                trackColor = statusColor.copy(alpha = 0.2f)
                            )
                            Spacer(Modifier.height(8.dp))
                            Text(
                                "$scanProgress%",
                                style = MaterialTheme.typography.labelLarge,
                                color = statusColor
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun SummaryRow(
    result: ScanResult,
    selectedSeverity: Severity?,
    onSeverityClick: (Severity) -> Unit
) {
    val isDark = MaterialTheme.colorScheme.surface.luminance() < 0.5f
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        SummaryChip(
            label = "${result.highRiskCount} High",
            color = hardDetectionColor(isDark),
            selected = selectedSeverity == Severity.HIGH,
            modifier = Modifier.weight(1f),
            onClick = { onSeverityClick(Severity.HIGH) }
        )
        SummaryChip(
            label = "${result.warningCount} Warning",
            color = warningColor(isDark),
            selected = selectedSeverity == Severity.WARNING,
            modifier = Modifier.weight(1f),
            onClick = { onSeverityClick(Severity.WARNING) }
        )
    }
}

@Composable
fun SummaryChip(
    label: String,
    color: Color,
    selected: Boolean,
    modifier: Modifier = Modifier,
    onClick: () -> Unit
) {
    val isDark = MaterialTheme.colorScheme.surface.luminance() < 0.5f
    val containerAlpha = when {
        selected && isDark -> 0.32f
        selected -> 0.30f
        isDark -> 0.2f
        else -> 0.20f
    }
    val borderColor = if (selected) color.copy(alpha = if (isDark) 0.85f else 0.55f) else Color.Transparent
    Surface(
        modifier = modifier,
        shape = RoundedCornerShape(12.dp),
        color = color.copy(alpha = containerAlpha),
        border = androidx.compose.foundation.BorderStroke(1.dp, borderColor)
    ) {
        Box(
            contentAlignment = Alignment.Center,
            modifier = Modifier
                .clickable(onClick = onClick)
                .padding(vertical = 10.dp)
        ) {
            Text(
                label,
                style = MaterialTheme.typography.labelMedium,
                fontWeight = FontWeight.SemiBold,
                color = color
            )
        }
    }
}

@Composable
@OptIn(ExperimentalFoundationApi::class)
fun CheckResultCard(item: CheckResult) {
    var expanded by remember { mutableStateOf(false) }
    val isDark = MaterialTheme.colorScheme.surface.luminance() < 0.5f
    val clipboardManager = LocalClipboardManager.current

    val severityColor = when (item.severity) {
        Severity.HIGH    -> hardDetectionColor(isDark)
        Severity.WARNING -> warningColor(isDark)
    }
    val accentColor = when (item.status) {
        CheckStatus.DETECTED -> severityColor
        CheckStatus.ERROR -> MaterialTheme.colorScheme.error
        CheckStatus.SKIPPED, CheckStatus.UNSUPPORTED -> MaterialTheme.colorScheme.outline
        CheckStatus.NOT_DETECTED -> passColor(isDark)
    }
    val accentContent = if (isDark) accentColor.copy(alpha = 0.88f) else accentColor
    val accentContainer = accentColor.copy(alpha = if (isDark) 0.14f else 0.12f)
    val accentSurface = accentColor.copy(alpha = if (isDark) 0.22f else 0.18f)

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .combinedClickable(
                onClick = {
                    if (item.status != CheckStatus.NOT_DETECTED) expanded = !expanded
                },
                onLongClick = {
                    clipboardManager.setText(AnnotatedString(buildDetectionCopyText(item)))
                }
            ),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = accentContainer),
        elevation = CardDefaults.cardElevation(defaultElevation = 0.dp)
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Box(
                    modifier = Modifier
                        .size(40.dp)
                        .clip(CircleShape)
                        .background(accentSurface),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(
                        imageVector = categoryIcon(item.category),
                        contentDescription = null,
                        tint = accentContent,
                        modifier = Modifier.size(20.dp)
                    )
                }

                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        item.name,
                        style = MaterialTheme.typography.bodyLarge,
                        fontWeight = FontWeight.SemiBold,
                        color = accentContent
                    )
                    Text(
                        item.description,
                        style = MaterialTheme.typography.bodySmall,
                        color = accentContent.copy(alpha = if (isDark) 0.72f else 0.82f),
                        maxLines = 2,
                        overflow = TextOverflow.Ellipsis
                    )
                    Spacer(Modifier.height(6.dp))
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Surface(
                            shape = RoundedCornerShape(999.dp),
                            color = accentSurface
                        ) {
                            Text(
                                categoryLabel(item.category),
                                modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp),
                                style = MaterialTheme.typography.labelSmall,
                                fontWeight = FontWeight.Medium,
                                color = accentContent.copy(alpha = if (isDark) 0.86f else 0.92f)
                            )
                        }
                        if (item.status != CheckStatus.NOT_DETECTED) {
                            Text(
                                "Hold to copy",
                                style = MaterialTheme.typography.labelSmall,
                                color = accentContent.copy(alpha = if (isDark) 0.62f else 0.72f)
                            )
                        }
                    }
                }

                Surface(
                    shape = RoundedCornerShape(8.dp),
                    color = accentSurface
                ) {
                    Text(
                        when (item.status) {
                            CheckStatus.DETECTED -> "FOUND"
                            CheckStatus.NOT_DETECTED -> "PASS"
                            CheckStatus.ERROR -> "ERROR"
                            CheckStatus.SKIPPED -> "SKIPPED"
                            CheckStatus.UNSUPPORTED -> "N/A"
                        },
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
                        style = MaterialTheme.typography.labelSmall,
                        fontWeight = FontWeight.Bold,
                        color = accentContent
                    )
                }
            }

            AnimatedVisibility(visible = expanded && item.status != CheckStatus.NOT_DETECTED) {
                Column {
                    Spacer(Modifier.height(10.dp))
                    HorizontalDivider(color = accentContent.copy(alpha = if (isDark) 0.16f else 0.2f))
                    Spacer(Modifier.height(10.dp))

                    val detail = item.detail
                    if (detail != null) {
                        Text(
                            "Detail",
                            style = MaterialTheme.typography.labelMedium,
                            color = accentContent.copy(alpha = if (isDark) 0.78f else 0.9f),
                            fontWeight = FontWeight.SemiBold
                        )
                        Spacer(Modifier.height(4.dp))
                        Text(
                            detail,
                            style = MaterialTheme.typography.bodySmall,
                            color = accentContent,
                            fontFamily = FontFamily.Monospace
                        )
                        Spacer(Modifier.height(12.dp))
                    }

                }
            }
        }
    }
}

private fun categoryIcon(category: CheckCategory): ImageVector = when (category) {
    CheckCategory.SU_BINARIES   -> Icons.Outlined.Terminal
    CheckCategory.ROOT_APPS     -> Icons.Outlined.Apps
    CheckCategory.SYSTEM_PROPS  -> Icons.Outlined.Settings
    CheckCategory.MOUNT_POINTS  -> Icons.Outlined.FolderOpen
    CheckCategory.BUILD_TAGS    -> Icons.Outlined.Label
    CheckCategory.BUSYBOX       -> Icons.Outlined.Code
    CheckCategory.WRITABLE_PATHS -> Icons.Outlined.Lock
    CheckCategory.MAGISK        -> Icons.Outlined.Security
    CheckCategory.FRIDA         -> Icons.Outlined.BugReport
    CheckCategory.EMULATOR      -> Icons.Outlined.PhoneAndroid
    CheckCategory.CUSTOM_ROM    -> Icons.Outlined.Smartphone
    CheckCategory.INTEGRITY     -> Icons.Outlined.VerifiedUser
    CheckCategory.SCANNER       -> Icons.Outlined.Memory
}

private fun categoryLabel(category: CheckCategory): String = when (category) {
    CheckCategory.SU_BINARIES -> "SU"
    CheckCategory.ROOT_APPS -> "Apps"
    CheckCategory.SYSTEM_PROPS -> "Props"
    CheckCategory.MOUNT_POINTS -> "Mounts"
    CheckCategory.BUILD_TAGS -> "Build"
    CheckCategory.BUSYBOX -> "Binaries"
    CheckCategory.WRITABLE_PATHS -> "Paths"
    CheckCategory.MAGISK -> "Runtime"
    CheckCategory.FRIDA -> "Frida"
    CheckCategory.EMULATOR -> "Emulator"
    CheckCategory.CUSTOM_ROM -> "ROM"
    CheckCategory.INTEGRITY -> "Integrity"
    CheckCategory.SCANNER -> "Scanner"
}

private fun buildDetectionCopyText(item: CheckResult): String {
    val state = when (item.status) {
        CheckStatus.DETECTED -> "FOUND"
        CheckStatus.NOT_DETECTED -> "PASS"
        CheckStatus.ERROR -> "ERROR"
        CheckStatus.SKIPPED -> "SKIPPED"
        CheckStatus.UNSUPPORTED -> "UNSUPPORTED"
    }
    return buildString {
        append("[${item.severity}] ${item.name}: $state")
        append('\n')
        append(item.description)
        if (!item.detail.isNullOrBlank()) {
            append('\n')
            append('\n')
            append(item.detail)
        }
    }
}
