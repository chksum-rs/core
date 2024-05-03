use std::path::{Path, PathBuf};

use async_trait::async_trait;
use tokio::fs::{metadata, read_dir, DirEntry, File, ReadDir};
use tokio::io::{AsyncBufReadExt as _, BufReader, Stdin};

use crate::{AsyncChksumable, Hash, Hashable, Result};

macro_rules! impl_async_chksumable {
    ($($t:ty),+ => $i:tt) => {
        $(
            #[async_trait]
            impl AsyncChksumable for $t $i
        )*
    };
}

impl_async_chksumable!(Path, &Path, &mut Path => {
    async fn chksum_with<H>(&mut self, hash: &mut H) -> Result<()>
    where
        H: Hash + Send,
    {
        let metadata = metadata(&self).await?;
        if metadata.is_dir() {
            read_dir(self).await?.chksum_with(hash).await
        } else {
            // everything treat as a file when it is not a directory
            File::open(self).await?.chksum_with(hash).await
        }
    }

});

impl_async_chksumable!(PathBuf, &PathBuf, &mut PathBuf => {
    async fn chksum_with<H>(&mut self, hash: &mut H) -> Result<()>
    where
        H: Hash + Send,
    {
        self.as_path().chksum_with(hash).await
    }
});

// TODO: missing `&File` implementation
impl_async_chksumable!(File, &mut File => {
    async fn chksum_with<H>(&mut self, hash: &mut H) -> Result<()>
    where
        H: Hash + Send,
    {
        // TODO: tracking issue [tokio-rs/tokio#6407](github.com/tokio-rs/tokio/issues/6407)
        // if self.is_terminal() {
        //     return Err(Error::IsTerminal);
        // }

        let mut reader = BufReader::new(self);
        loop {
            let buffer = reader.fill_buf().await?;
            let length = buffer.len();
            if length == 0 {
                break;
            }
            buffer.hash_with(hash);
            reader.consume(length);
        }
        Ok(())
    }
});

impl_async_chksumable!(DirEntry, &DirEntry, &mut DirEntry => {
    async fn chksum_with<H>(&mut self, hash: &mut H) -> Result<()>
    where
        H: Hash + Send,
    {
        self.path().chksum_with(hash).await
    }
});

impl_async_chksumable!(ReadDir, &mut ReadDir => {
    async fn chksum_with<H>(&mut self, hash: &mut H) -> Result<()>
    where
        H: Hash + Send,
    {
        let mut dir_entries = Vec::new();
        while let Some(dir_entry) = self.next_entry().await? {
            dir_entries.push(dir_entry);
        }
        dir_entries.sort_by_key(DirEntry::path);
        for mut dir_entry in dir_entries {
            dir_entry.chksum_with(hash).await?;
        }
        Ok(())
    }
});

// TODO: missing `&Stdin` implementation
impl_async_chksumable!(Stdin, &mut Stdin => {
    async fn chksum_with<H>(&mut self, hash: &mut H) -> Result<()>
    where
        H: Hash + Send,
    {
        // TODO: tracking issue [tokio-rs/tokio#6407](github.com/tokio-rs/tokio/issues/6407)
        // if self.is_terminal() {
        //     return Err(Error::IsTerminal);
        // }

        let mut reader = BufReader::new(self);
        loop {
            let buffer = reader.fill_buf().await?;
            let length = buffer.len();
            if length == 0 {
                break;
            }
            buffer.hash_with(hash);
            reader.consume(length);
        }
        Ok(())
    }
});
