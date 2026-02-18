package com.mega.provider

import android.graphics.BitmapFactory
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ImageView
import android.widget.ProgressBar
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.RecyclerView
import androidx.viewpager2.widget.ViewPager2
import kotlinx.coroutines.*

class PhotoViewerActivity : AppCompatActivity() {

    companion object {
        const val EXTRA_HANDLES = "handles"   // ArrayList<String>
        const val EXTRA_NAMES   = "names"     // ArrayList<String>
        const val EXTRA_INDEX   = "index"     // Int — start position
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_photo_viewer)

        val handles = intent.getStringArrayListExtra(EXTRA_HANDLES) ?: return finish()
        val names   = intent.getStringArrayListExtra(EXTRA_NAMES)   ?: ArrayList()
        val index   = intent.getIntExtra(EXTRA_INDEX, 0)

        val pager = findViewById<ViewPager2>(R.id.photo_pager)
        pager.adapter = PhotoAdapter(handles)
        pager.setCurrentItem(index, false)

        supportActionBar?.apply {
            setDisplayHomeAsUpEnabled(true)
            title = names.getOrNull(index) ?: "Photo"
        }

        pager.registerOnPageChangeCallback(object : ViewPager2.OnPageChangeCallback() {
            override fun onPageSelected(position: Int) {
                supportActionBar?.title = names.getOrNull(position) ?: "Photo"
            }
        })
    }

    override fun onSupportNavigateUp(): Boolean { finish(); return true }

    inner class PhotoAdapter(private val handles: List<String>) :
        RecyclerView.Adapter<PhotoAdapter.VH>() {

        inner class VH(v: View) : RecyclerView.ViewHolder(v) {
            val image: ImageView = v.findViewById(R.id.photo_image)
            val progress: ProgressBar = v.findViewById(R.id.photo_progress)
        }

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int) =
            VH(LayoutInflater.from(parent.context).inflate(R.layout.item_photo, parent, false))

        override fun getItemCount() = handles.size

        override fun onBindViewHolder(vh: VH, pos: Int) {
            vh.image.setImageBitmap(null)
            vh.progress.visibility = View.VISIBLE

            CoroutineScope(Dispatchers.IO).launch {
                try {
                    val bytes = MegaClientHolder.getDecryptedBytes(handles[pos])
                    val bmp = BitmapFactory.decodeByteArray(bytes, 0, bytes.size)
                    withContext(Dispatchers.Main) {
                        if (vh.adapterPosition == pos) {
                            vh.image.setImageBitmap(bmp)
                            vh.progress.visibility = View.GONE
                        }
                    }
                } catch (e: Exception) {
                    withContext(Dispatchers.Main) {
                        vh.progress.visibility = View.GONE
                    }
                }
            }
        }
    }
}
