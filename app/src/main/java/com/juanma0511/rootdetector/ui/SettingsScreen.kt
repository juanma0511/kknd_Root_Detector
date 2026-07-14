package com.juanma0511.rootdetector.ui

import com.juanma0511.rootdetector.R
import android.app.Activity
import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.DarkMode
import androidx.compose.material.icons.filled.LightMode
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import android.os.Build
import androidx.compose.ui.unit.sp
import coil.compose.AsyncImage
import coil.request.ImageRequest

data class Contributor(
    val login: String,
    val displayName: String,
    val role: String,
    val bio: String,
    val avatarUrl: String,
    val profileUrl: String
)

private val CONTRIBUTORS = listOf(
    Contributor(
        login = "juanma0511",
        displayName = "Juan Ma",
        role = "Developer",
        bio = "",
        avatarUrl = "https://avatars.githubusercontent.com/u/121111348?v=4",
        profileUrl = "https://github.com/juanma0511"
    ),
    Contributor(
        login = "OukaroMF",
        displayName = "OukaroMF",
        role = "Artist",
        bio = "Created the app's artwork and visual assets",
        avatarUrl = "https://avatars.githubusercontent.com/u/107784230?v=4",
        profileUrl = "https://github.com/OukaroMF"
    ),
    Contributor(
        login = "salihefee",
        displayName = "salihefee",
        role = "Contributor",
        bio = "Cleaned up duplicate detection descriptions",
        avatarUrl = "https://avatars.githubusercontent.com/u/61908056?v=4",
        profileUrl = "https://github.com/salihefee"
    ),
    Contributor(
        login = "WaggBR",
        displayName = "WaggBR",
        role = "Translator",
        bio = "Added Portuguese (BR) translations",
        avatarUrl = "https://avatars.githubusercontent.com/u/57603689?v=4",
        profileUrl = "https://github.com/WaggBR"
    ),
    Contributor(
        login = "originalFactor",
        displayName = "originalFactor",
        role = "Contributor",
        bio = "Fixed artwork assets for platform compatibility",
        avatarUrl = "https://avatars.githubusercontent.com/u/72148355?v=4",
        profileUrl = "https://github.com/originalFactor"
    )
)

@Composable
fun SettingsScreen(
    currentTheme: ThemeMode,
    onThemeChange: (ThemeMode) -> Unit
) {
    val context = LocalContext.current

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(start = 16.dp, end = 16.dp, top = 8.dp, bottom = 104.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {

        SettingsSection(title = stringResource(R.string.appearance)) {
            ThemeSelector(currentTheme = currentTheme, onThemeChange = onThemeChange)
        }

        SettingsSection(title = stringResource(R.string.about)) {
            CreditsCard(
                contributors = CONTRIBUTORS,
                onProfileClick = { url -> openExternalUrl(context, url) }
            )
        }

        Spacer(Modifier.height(16.dp))

        Text(
            stringResource(R.string.app_name_footer),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.5f),
            modifier = Modifier.fillMaxWidth(),
            textAlign = TextAlign.Center
        )
    }
}

private fun openExternalUrl(context: Context, url: String) {
    val intent = Intent(Intent.ACTION_VIEW, Uri.parse(url)).apply {
        addCategory(Intent.CATEGORY_BROWSABLE)
        if (context !is Activity) {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
    }
    val chooser = Intent.createChooser(intent, null).apply {
        if (context !is Activity) {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
    }
    runCatching {
        if (intent.resolveActivity(context.packageManager) != null) {
            context.startActivity(chooser)
        }
    }
}

@Composable
fun SettingsSection(
    title: String,
    content: @Composable ColumnScope.() -> Unit
) {
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text(
            title.uppercase(java.util.Locale.getDefault()),
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.primary,
            fontWeight = FontWeight.Bold,
            modifier = Modifier.padding(horizontal = 4.dp, vertical = 4.dp)
        )
        Card(
            shape = RoundedCornerShape(16.dp),
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.4f)
            ),
            elevation = CardDefaults.cardElevation(0.dp)
        ) {
            Column(modifier = Modifier.padding(4.dp)) {
                content()
            }
        }
    }
}

@Composable
fun ThemeSelector(
    currentTheme: ThemeMode,
    onThemeChange: (ThemeMode) -> Unit
) {
    Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(
                Icons.Outlined.Palette,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.primary,
                modifier = Modifier.size(20.dp)
            )
            Spacer(Modifier.width(10.dp))
            Text(
                stringResource(R.string.theme),
                style = MaterialTheme.typography.bodyLarge,
                fontWeight = FontWeight.Medium
            )
        }

        Spacer(Modifier.height(4.dp))

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            ThemeChip(
                label = stringResource(R.string.system),
                icon = Icons.Outlined.SettingsBrightness,
                selected = currentTheme == ThemeMode.SYSTEM,
                onClick = { onThemeChange(ThemeMode.SYSTEM) },
                modifier = Modifier.weight(1f)
            )
            ThemeChip(
                label = stringResource(R.string.light),
                icon = Icons.Filled.LightMode,
                selected = currentTheme == ThemeMode.LIGHT,
                onClick = { onThemeChange(ThemeMode.LIGHT) },
                modifier = Modifier.weight(1f)
            )
            ThemeChip(
                label = stringResource(R.string.dark),
                icon = Icons.Filled.DarkMode,
                selected = currentTheme == ThemeMode.DARK,
                onClick = { onThemeChange(ThemeMode.DARK) },
                modifier = Modifier.weight(1f)
            )
        }
    }
}

@Composable
fun ThemeChip(
    label: String,
    icon: ImageVector,
    selected: Boolean,
    onClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    val bg = if (selected) MaterialTheme.colorScheme.primary
             else MaterialTheme.colorScheme.surfaceVariant
    val fg = if (selected) MaterialTheme.colorScheme.onPrimary
             else MaterialTheme.colorScheme.onSurfaceVariant

    Surface(
        modifier = modifier
            .clip(RoundedCornerShape(12.dp))
            .clickable { onClick() },
        shape = RoundedCornerShape(12.dp),
        color = bg
    ) {
        Column(
            modifier = Modifier.padding(vertical = 12.dp, horizontal = 8.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(4.dp)
        ) {
            Icon(icon, contentDescription = label, tint = fg, modifier = Modifier.size(20.dp))
            Text(label, style = MaterialTheme.typography.labelMedium, color = fg,
                fontWeight = if (selected) FontWeight.SemiBold else FontWeight.Normal)
        }
    }
}

@Composable
fun ContributorRow(
    contributor: Contributor,
    onProfileClick: (String) -> Unit,
    showDivider: Boolean
) {
    val context = LocalContext.current
    Column {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 12.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(14.dp)
        ) {
            AsyncImage(
                model = ImageRequest.Builder(context)
                    .data(contributor.avatarUrl)
                    .crossfade(true)
                    .build(),
                contentDescription = contributor.displayName,
                modifier = Modifier
                    .size(48.dp)
                    .clip(CircleShape)
            )

            Column(modifier = Modifier.weight(1f)) {
                Text(
                    contributor.displayName,
                    style = MaterialTheme.typography.bodyLarge,
                    fontWeight = FontWeight.SemiBold
                )
                Text(
                    contributor.role,
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.primary,
                    fontWeight = FontWeight.Medium
                )
                if (contributor.bio.isNotEmpty()) {
                    Spacer(Modifier.height(2.dp))
                    Text(
                        contributor.bio,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }

            IconButton(
                onClick = { onProfileClick(contributor.profileUrl) },
                modifier = Modifier.size(36.dp)
            ) {
                Icon(
                    Icons.Outlined.Code,
                    contentDescription = "GitHub",
                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.size(18.dp)
                )
            }
        }

        if (showDivider) {
            HorizontalDivider(
                modifier = Modifier.padding(horizontal = 16.dp),
                color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.4f)
            )
        }
    }
}

@Composable
fun CreditsCard(
    contributors: List<Contributor>,
    onProfileClick: (String) -> Unit
) {
    Column(modifier = Modifier.padding(vertical = 4.dp)) {
        contributors.forEachIndexed { index, contributor ->
            ContributorRow(
                contributor = contributor,
                onProfileClick = onProfileClick,
                showDivider = index < contributors.lastIndex
            )
        }

        HorizontalDivider(
            modifier = Modifier.padding(horizontal = 16.dp),
            color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.4f)
        )

        Text(
            stringResource(R.string.built_with),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.7f),
            textAlign = TextAlign.Center,
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 12.dp)
        )
    }
}
