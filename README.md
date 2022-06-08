# Laporan Tugas Akhir
 Nama : Fauzan Adzima Tohari
 </br> NIM : 205150301111029
 </br>Mata Kuliah : Arsitektur Jaringan Terkini
 </br>Program Studi : Teknik Komputer
#
# Kata Pengantar
Puji syukur kehadirat Tuhan Yang Maha Esa yang telah memberikan rahmat dan hidayah-Nya sehingga saya dapat dengan lancar menyusun laporan tugas akhir ini guna melengkapi tugas dari mata kuliah Arsitektur Jaringan Terkini. Laporan tugas akhir ini berisikan 4 bagian utama kegiatan pengulangan tugas yang pernah diberikan yakni dimulai dari tugas 1 hingga tugas 4. Saya sebagai penulis berharap semoga laporan yang telah saya buat sedemikian rupa dapat diterima dengan baik. Jika di dalam laporan ini terdapat kesalahan atau kekurangan, saya meminta permohonan maaf sebesar - besarnya. Demikian yang bisa saya sampaikan, saya ucapkan terima kasih.
# <b>TUGAS 1
</br> A. Pembuatan EC2 Instance di AWS Academy </b>
</br>Di dalam pembuatan dan melakukan pengerjaan tugas akhir ini, kita menggunakan salah satu platform cloud yakni Amazon Web Services (AWS) Academy. Sebelum masuk ke dalam pembahasan bagian utama, kita perlu memulainya dengan login akun AWS Academy terlebih dahulu. Setelah melakukan login, kita melanjutkan dengan membuat instance baru sesuai dengan ketentuan yang diberikan. Langkah - langkah dalam pembuatan instance sebagai berikut :

</br>Spesifikasi Instance :
</br> Name and tags: Tugas Akhir
</br> OS Images: Ubuntu Server 22.04 LTS 64 bit
</br> Instance type: t2.medium
</br> Key pair: vockey
</br> Edit Network settings: allow SSH, allow HTTP, allow HTTPS, allow TCP port 8080, allow TCP port 8081
</br> Configure storage: 30 GiB, gp3

</br> 1. Melakukan Name and tags: Tugas Akhir dan Melakukan pemilihan OS Images: Ubuntu Server 22.04 LTS 64 bit
</br> ![1  Nama Instances](https://user-images.githubusercontent.com/82666388/172537517-aef17425-ac86-4469-ab0c-33f8631e89ca.png)
</br></br> 2. Melakukan pemilihan Instance type: t2.medium dan  Key pair: vockey
</br>![2](https://user-images.githubusercontent.com/82666388/172538485-e66ce82c-71a5-4451-81b5-b23557be178a.png)
</br></br>3. Melakukan Edit Network settings: allow SSH, allow HTTP, allow HTTPS, allow TCP port 8080, allow TCP port 8081
</br>![3](https://user-images.githubusercontent.com/82666388/172538616-86c7d216-7f86-4da5-a887-318d29f27e5c.png)
</br></br>4. Melakukan Configure storage: 30 GiB, gp3
</br>![4](https://user-images.githubusercontent.com/82666388/172541772-01aca3c9-9b90-4f5f-9b51-405e2381cfcf.png)
</br></br>5. Berhasil membuat instance
</br>![5](https://user-images.githubusercontent.com/82666388/172541835-7d60efb3-6e20-4668-8280-bec47f7e7485.png)
</br></br>Setelah Selesai Melakukan Konfigurasi EC2, Saya akan menghubungkannya dengan terminal ubuntu
</br></br>6. Melakukan Update di dalam ubuntu
</br>![6](https://user-images.githubusercontent.com/82666388/172541878-22b87ea7-10a3-428c-b2c1-b694e1e7d0af.png)
</br></br>7. Unduh repositori Mininet
</br>![7](https://user-images.githubusercontent.com/82666388/172543773-a6e89313-b1f1-47e3-a56e-15b93e2581b4.png)
</br></br>8. Instal mininet
</br>![8](https://user-images.githubusercontent.com/82666388/172543801-ab1895aa-330d-4441-9d5c-297243b301e8.png)
</br></br>9. Unduh repository Ryu dan instal
</br>![9](https://user-images.githubusercontent.com/82666388/172543823-d82ee390-2db2-457a-aab3-4074820ee7c7.png)
</br></br>10. melakukan install pip
</br>![10](https://user-images.githubusercontent.com/82666388/172543848-8b35cf14-316a-417f-98e5-dd6825daf5d0.png)
</br></br>11. Unduh repository Flowmanager
</br> ![11](https://user-images.githubusercontent.com/82666388/172566688-7a2db033-b7fe-4845-8cfb-e35d151b7b83.png)
</br>

# </br><b>TUGAS 2</b> 
</br><b> A. Pembuatan Custom Topology Mininet Seperti pada Modul Tugas 2</b>
 </br>1. Pembuatan File berisi konfigurasi berekstensi .py
 </br>![1](https://user-images.githubusercontent.com/82666388/172558074-713b9197-9acf-4f4b-aed0-a3ba08a9497f.png)
 </br>2. Menjalankan mininet tanpa controller menggunakan custom topo yang sudah dibuat
 </br>![2](https://user-images.githubusercontent.com/82666388/172558121-3cf8e147-cf91-4dfb-bf7b-f19eec024861.png)
 </br>3. Masuk ke mode mininet dengan perintah sudo mn
 </br>![3](https://user-images.githubusercontent.com/82666388/172567787-8d15d113-49c7-497e-b8fc-1f570bb03932.png)
 </br>4. Menguji koneksi agar h1 dengan h2
 </br>![4](https://user-images.githubusercontent.com/82666388/172558193-4f0ba675-3df5-4706-8ff2-e6aa496361b3.png)
 </br></br>B.Tugas membuat program untuk custom topology
 </br>
