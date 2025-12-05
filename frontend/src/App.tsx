import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Terminal,
  Upload,
  CheckCircle2,
  File as FileIcon,
  RefreshCcw,
  Eye,
  EyeOff,
  Copy,
  History,
  Trash2,
  Download,
  Wand2,
} from "lucide-react";
import { Button } from "./components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "./components/ui/tabs";

type TabValue = "home" | "files";
type ValueField = "original_hash" | "signature" | "post_signature_hash";

interface FileRecord {
  id: string;
  file_name: string;
  user_id?: string;
  file_size?: number;
  storage_path?: string;
  original_hash?: string | null;
  signature?: string | null;
  post_signature_hash?: string | null;
  public_key_hash?: string | null;
  created_at?: string;
  updated_at?: string;
}

interface FileVersion {
  id: string;
  file_id: string;
  user_id?: string;
  signature?: string | null;
  post_signature_hash?: string | null;
  change_reason?: string | null;
  created_at: string;
  editor_id?: string | null;
}

interface VersionModalState {
  fileId: string;
  fileName: string;
  versions: FileVersion[];
}

type AlertTone = "success" | "error" | "info";

interface UploadAlert {
  id: number;
  tone: AlertTone;
  text: string;
}

type ToastTone = "success" | "error" | "info";

interface ToastState {
  id: number;
  tone: ToastTone;
  message: string;
}

const DEMO_USER_ID = "00000000-0000-0000-0000-000000000000";
const API_BASE =
  typeof window !== "undefined" ? window.location.origin : "http://localhost:5000";

const visibilityKey = (fileId: string, field: ValueField) => `${fileId}:${field}`;

const maskedValue = (value?: string | null) => {
  if (!value) {
    return "";
  }
  const length = Math.min(value.length, 64);
  return "•".repeat(length || 16);
};

const formatSize = (size?: number) => {
  if (!size || Number.isNaN(size)) {
    return "0.00 KB";
  }
  return `${(size / 1024).toFixed(2)} KB`;
};

const formatDate = (iso?: string) => {
  if (!iso) {
    return "Unknown";
  }
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) {
    return iso;
  }
  return date.toLocaleString();
};

const truncate = (value: string, length = 32) => {
  if (value.length <= length) {
    return value;
  }
  return `${value.slice(0, length)}…`;
};

// Helper function to safely parse JSON responses
const parseJsonResponse = async (response: Response): Promise<any> => {
  const contentType = response.headers.get("content-type");
  
  // Read the response text once (can only be read once)
  const text = await response.text();
  
  // Check if response is JSON
  if (!contentType || !contentType.includes("application/json")) {
    console.error("Non-JSON response received:", text.substring(0, 200));
    throw new Error(`Server returned invalid response: ${text.substring(0, 100)}`);
  }
  
  // Parse JSON with error handling
  if (!text.trim()) {
    throw new Error("Empty response body");
  }
  
  try {
    return JSON.parse(text);
  } catch (error) {
    if (error instanceof SyntaxError) {
      console.error("Invalid JSON received:", error.message);
      throw new Error(`Server returned invalid JSON: ${error.message}`);
    }
    throw error;
  }
};

export default function App() {
  const [activeTab, setActiveTab] = useState<TabValue>("home");
  const [selectedFiles, setSelectedFiles] = useState<File[]>([]);
  const [uploadAlerts, setUploadAlerts] = useState<UploadAlert[]>([]);
  const [isDragging, setIsDragging] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [currentFiles, setCurrentFiles] = useState<FileRecord[]>([]);
  const [loadingFiles, setLoadingFiles] = useState(false);
  const [visibleValues, setVisibleValues] = useState<Record<string, boolean>>({});
  const [editingFileId, setEditingFileId] = useState<string | null>(null);
  const [editingSignature, setEditingSignature] = useState("");
  const [savingSignature, setSavingSignature] = useState(false);
  const [generatingFileId, setGeneratingFileId] = useState<string | null>(null);
  const [versionModal, setVersionModal] = useState<VersionModalState | null>(null);
  const [revertingVersionId, setRevertingVersionId] = useState<string | null>(null);
  const [toast, setToast] = useState<ToastState | null>(null);
  const [fileInputKey, setFileInputKey] = useState(0);
  const [showHashes, setShowHashes] = useState(true);

  const showToast = useCallback((message: string, tone: ToastTone) => {
    setToast({
      id: Date.now(),
      tone,
      message,
    });
  }, []);

  useEffect(() => {
    if (!toast) {
      return;
    }
    const timer = setTimeout(() => setToast(null), 2800);
    return () => clearTimeout(timer);
  }, [toast]);

  const pushUploadAlert = useCallback((tone: AlertTone, text: string) => {
    setUploadAlerts((prev) => [
      ...prev,
      {
        id: Date.now() + Math.random(),
        tone,
        text,
      },
    ]);
  }, []);

  const isValueVisible = useCallback(
    (fileId: string, field: ValueField) => !!visibleValues[visibilityKey(fileId, field)],
    [visibleValues],
  );

  const toggleVisibility = useCallback((fileId: string, field: ValueField) => {
    const key = visibilityKey(fileId, field);
    setVisibleValues((prev) => ({
      ...prev,
      [key]: !prev[key],
    }));
  }, []);

  const copyToClipboard = useCallback(
    async (value?: string | null) => {
      if (!value) {
        return;
      }
      try {
        await navigator.clipboard.writeText(value);
        showToast("Copied to clipboard", "success");
      } catch {
        try {
          const textarea = document.createElement("textarea");
          textarea.value = value;
          textarea.style.position = "fixed";
          textarea.style.opacity = "0";
          document.body.appendChild(textarea);
          textarea.focus();
          textarea.select();
          document.execCommand("copy");
          document.body.removeChild(textarea);
          showToast("Copied to clipboard", "success");
        } catch {
          showToast("Failed to copy value", "error");
        }
      }
    },
    [showToast],
  );

  const loadFiles = useCallback(async () => {
    setLoadingFiles(true);
    try {
      const response = await fetch(`${API_BASE}/api/files?user_id=${DEMO_USER_ID}`);
      
      const data = (await parseJsonResponse(response)) as { files?: FileRecord[]; error?: string };
      if (!response.ok) {
        showToast(data.error ?? "Failed to load files", "error");
        return;
      }
      const files = data.files ?? [];
      setCurrentFiles(files);
      setVisibleValues((prev) => {
        if (!files.length) {
          return {};
        }
        const next: Record<string, boolean> = {};
        files.forEach((file) => {
          (["original_hash", "signature", "post_signature_hash"] as ValueField[]).forEach(
            (field) => {
              const key = visibilityKey(file.id, field);
              if (prev[key]) {
                next[key] = true;
              }
            },
          );
        });
        return next;
      });
    } catch (error) {
      console.error("Error loading files", error);
      const errorMessage = error instanceof Error ? error.message : "Unable to load files";
      showToast(errorMessage.includes("invalid response") ? "Server returned invalid response. Please check the API configuration." : "Unable to load files", "error");
    } finally {
      setLoadingFiles(false);
    }
  }, [showToast]);

  useEffect(() => {
    loadFiles().catch((err) => console.error("Initial load error", err));
  }, [loadFiles]);

  useEffect(() => {
    if (activeTab === "files") {
      loadFiles().catch((err) => console.error("Reload error", err));
    }
  }, [activeTab, loadFiles]);

  const handleFileSelection = useCallback((files: File[]) => {
    if (!files.length) {
      return;
    }
    const txtFiles = files.filter((file) => file.name.toLowerCase().endsWith(".txt"));
    if (txtFiles.length !== files.length) {
      pushUploadAlert("info", "Only .txt files are accepted. Non-text files were ignored.");
    }
    if (!txtFiles.length) {
      return;
    }
    setSelectedFiles(txtFiles);
  }, [pushUploadAlert]);

  const handleFileInputChange = useCallback(
    (event: React.ChangeEvent<HTMLInputElement>) => {
      if (!event.target.files) {
        return;
      }
      handleFileSelection(Array.from(event.target.files));
      setUploadAlerts([]);
    },
    [handleFileSelection],
  );

  const handleDrop = useCallback(
    (event: React.DragEvent<HTMLDivElement>) => {
      event.preventDefault();
      setIsDragging(false);
      if (!event.dataTransfer.files) {
        return;
      }
      handleFileSelection(Array.from(event.dataTransfer.files));
      setUploadAlerts([]);
    },
    [handleFileSelection],
  );

  const handleDragOver = useCallback((event: React.DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    setIsDragging(true);
  }, []);

  const handleDragLeave = useCallback(() => {
    setIsDragging(false);
  }, []);

  const uploadFiles = useCallback(async () => {
    if (!selectedFiles.length) {
      return;
    }
    setUploading(true);
    setUploadAlerts([]);

    const formData = new FormData();
    selectedFiles.forEach((file) => formData.append("files", file));
    formData.append("user_id", DEMO_USER_ID);

    try {
      const response = await fetch(`${API_BASE}/api/files`, {
        method: "POST",
        body: formData,
      });
      
      const data = (await parseJsonResponse(response)) as {
        files?: Array<{
          success: boolean;
          filename?: string;
          error?: string;
          error_type?: string;
        }>;
        error?: string;
      };
      if (!response.ok) {
        pushUploadAlert("error", data.error ?? "Upload failed");
        showToast("Upload failed", "error");
        return;
      }

      let successCount = 0;
      let failureCount = 0;

      for (const result of data.files ?? []) {
        if (result.success) {
          successCount += 1;
          pushUploadAlert(
            "success",
            `Uploaded ${result.filename ?? "file"} successfully.`,
          );
        } else {
          failureCount += 1;
          pushUploadAlert(
            "error",
            `${result.filename ?? "File"} failed: ${result.error ?? "Unknown error"}`,
          );
        }
      }

      if (!successCount && !failureCount) {
        pushUploadAlert("info", "No files were processed.");
      }

      if (successCount) {
        showToast(`Uploaded ${successCount} file(s).`, "success");
        setSelectedFiles([]);
        setFileInputKey((prev) => prev + 1);
        loadFiles().catch((err) => console.error("Reload after upload failed", err));
        setActiveTab("files");
      }

      if (failureCount) {
        showToast(`${failureCount} file(s) failed to upload`, "error");
      }
    } catch (error) {
      console.error("Upload error", error);
      const errorMessage = error instanceof Error ? error.message : "Upload failed. Check the server logs.";
      pushUploadAlert("error", errorMessage.includes("invalid response") ? "Server returned invalid response. Please check the API configuration." : "Upload failed. Check the server logs.");
      showToast(errorMessage.includes("invalid response") ? "Upload failed: Invalid server response" : "Upload failed", "error");
    } finally {
      setUploading(false);
    }
  }, [selectedFiles, pushUploadAlert, loadFiles, showToast]);

  const startEditingSignature = useCallback((file: FileRecord) => {
    setEditingFileId(file.id);
    setEditingSignature(file.signature ?? "");
  }, []);

  const cancelEditingSignature = useCallback(() => {
    setEditingFileId(null);
    setEditingSignature("");
  }, []);

  const saveSignature = useCallback(async () => {
    if (!editingFileId) {
      return;
    }
    const trimmed = editingSignature.trim();
    if (trimmed && !/^[a-fA-F0-9]{64}$/.test(trimmed)) {
      showToast("Signature must be 64 hexadecimal characters", "error");
      return;
    }

    setSavingSignature(true);
    try {
      const response = await fetch(`${API_BASE}/api/files/${editingFileId}/signature`, {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          signature: trimmed,
          user_id: DEMO_USER_ID,
          change_reason: "User edited signature",
        }),
      });
      const data = (await parseJsonResponse(response)) as { file?: FileRecord; error?: string };
      if (!response.ok) {
        showToast(data.error ?? "Failed to update signature", "error");
        return;
      }
      if (data.file) {
        setCurrentFiles((prev) =>
          prev.map((file) => (file.id === data.file?.id ? data.file : file)),
        );
      }
      showToast("Signature updated", "success");
      cancelEditingSignature();
      loadFiles().catch((err) => console.error("Reload after signature", err));
    } catch (error) {
      console.error("Signature save error", error);
      const errorMessage = error instanceof Error ? error.message : "Failed to update signature";
      showToast(errorMessage.includes("invalid response") ? "Server returned invalid response. Please check the API configuration." : "Failed to update signature", "error");
    } finally {
      setSavingSignature(false);
    }
  }, [editingFileId, editingSignature, cancelEditingSignature, loadFiles, showToast]);

  const generateSampleSignature = useCallback(
    async (file: FileRecord) => {
      const sampleSignature = Array.from({ length: 64 }, () =>
        Math.floor(Math.random() * 16).toString(16),
      ).join("");
      setGeneratingFileId(file.id);
      try {
        const response = await fetch(`${API_BASE}/api/files/${file.id}/signature`, {
          method: "PUT",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            signature: sampleSignature,
            user_id: DEMO_USER_ID,
            change_reason: "Generated sample signature",
          }),
        });
        const data = (await parseJsonResponse(response)) as { file?: FileRecord; error?: string };
        if (!response.ok) {
          showToast(data.error ?? "Unable to generate signature", "error");
          return;
        }
        if (data.file) {
          setCurrentFiles((prev) =>
            prev.map((f) => (f.id === data.file?.id ? data.file : f)),
          );
        }
        toggleVisibility(file.id, "signature");
        showToast("Sample signature generated", "success");
        loadFiles().catch((err) => console.error("Reload after generation", err));
      } catch (error) {
        console.error("Generate sample error", error);
        const errorMessage = error instanceof Error ? error.message : "Unable to generate sample signature";
        showToast(errorMessage.includes("invalid response") ? "Server returned invalid response. Please check the API configuration." : "Unable to generate sample signature", "error");
      } finally {
        setGeneratingFileId(null);
      }
    },
    [loadFiles, showToast, toggleVisibility],
  );

  const deleteFile = useCallback(
    async (file: FileRecord) => {
      if (
        !window.confirm(
          `Delete ${file.file_name}? This removes the file and its signatures permanently.`,
        )
      ) {
        return;
      }
      try {
        const response = await fetch(`${API_BASE}/api/files/${file.id}?user_id=${DEMO_USER_ID}`, {
          method: "DELETE",
        });
        const data = (await parseJsonResponse(response)) as { success?: boolean; error?: string };
        if (!response.ok) {
          showToast(data.error ?? "Failed to delete file", "error");
          return;
        }
        showToast("File deleted", "success");
        loadFiles().catch((err) => console.error("Reload after delete", err));
      } catch (error) {
        console.error("Delete error", error);
        const errorMessage = error instanceof Error ? error.message : "Failed to delete file";
        showToast(errorMessage.includes("invalid response") ? "Server returned invalid response. Please check the API configuration." : "Failed to delete file", "error");
      }
    },
    [loadFiles, showToast],
  );

  const downloadFile = useCallback((file: FileRecord) => {
    const url = `${API_BASE}/api/files/${file.id}/download?user_id=${DEMO_USER_ID}`;
    window.open(url, "_blank");
  }, []);

  const openVersionHistory = useCallback(
    async (file: FileRecord) => {
      try {
        const response = await fetch(
          `${API_BASE}/api/files/${file.id}/versions?user_id=${DEMO_USER_ID}`,
        );
        const data = (await parseJsonResponse(response)) as { versions?: FileVersion[]; error?: string };
        if (!response.ok) {
          showToast(data.error ?? "Failed to load version history", "error");
          return;
        }
        setVersionModal({
          fileId: file.id,
          fileName: file.file_name,
          versions: data.versions ?? [],
        });
      } catch (error) {
        console.error("Version history error", error);
        const errorMessage = error instanceof Error ? error.message : "Failed to load version history";
        showToast(errorMessage.includes("invalid response") ? "Server returned invalid response. Please check the API configuration." : "Failed to load version history", "error");
      }
    },
    [showToast],
  );

  const revertVersion = useCallback(
    async (fileId: string, versionId: string) => {
      setRevertingVersionId(versionId);
      try {
        const response = await fetch(`${API_BASE}/api/files/${fileId}/revert`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            version_id: versionId,
            user_id: DEMO_USER_ID,
          }),
        });
        const data = (await parseJsonResponse(response)) as { file?: FileRecord; error?: string };
        if (!response.ok) {
          showToast(data.error ?? "Failed to revert", "error");
          return;
        }
        showToast("Signature reverted", "success");
        setVersionModal(null);
        loadFiles().catch((err) => console.error("Reload after revert", err));
      } catch (error) {
        console.error("Revert error", error);
        const errorMessage = error instanceof Error ? error.message : "Failed to revert";
        showToast(errorMessage.includes("invalid response") ? "Server returned invalid response. Please check the API configuration." : "Failed to revert", "error");
      } finally {
        setRevertingVersionId(null);
      }
    },
    [loadFiles, showToast],
  );

  const uploadButtonLabel = uploading
    ? "Uploading…"
    : "Upload";

  const sortedFiles = useMemo(
    () =>
      [...currentFiles].sort((a, b) =>
        (b.updated_at ?? b.created_at ?? "").localeCompare(a.updated_at ?? a.created_at ?? ""),
      ),
    [currentFiles],
  );

  return (
    <div
      className="min-h-screen bg-black text-white flex items-center justify-center p-4"
      style={{ fontFamily: "monospace" }}
    >
      <div className="w-full max-w-4xl overflow-hidden" style={{ maxWidth: 'calc(100vw - 2rem)', width: '100%' }}>
        <div className="border border-white bg-black overflow-hidden w-full">
          <div className="border-b border-white px-4 py-3 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Terminal className="w-5 h-5" />
              <span className="tracking-wider">TERMINAL</span>
            </div>
            <div className="flex gap-2">
              <div className="w-3 h-3 border border-white" />
              <div className="w-3 h-3 border border-white" />
              <div className="w-3 h-3 border border-white" />
            </div>
          </div>

          <Tabs
            value={activeTab}
            onValueChange={(value) => setActiveTab(value as TabValue)}
            className="w-full"
          >
            <div className="border-b border-white">
              <TabsList className="w-full bg-black rounded-none border-0 h-auto p-0">
                <TabsTrigger
                  value="home"
                  className="rounded-none border-r border-white px-8 py-2 data-[state=active]:bg-white data-[state=active]:text-black text-white"
                >
                  Home
                </TabsTrigger>
                <TabsTrigger
                  value="files"
                  className="rounded-none px-8 py-2 data-[state=active]:bg-white data-[state=active]:text-black text-white"
                >
                  Files
                </TabsTrigger>
              </TabsList>
            </div>

            <TabsContent value="home" className="p-6 mt-0">
              <div className="mb-6 space-y-2">
                <div>
                  <span className="text-white">$ </span>
                  <span className="text-white">checkuvity --help</span>
                </div>
                <div className="text-gray-400 mb-4">
                  Upload the text file to get it signed and download the zip file
                </div>
              </div>

              <div className="mb-4">
                <span className="text-white">$ </span>
                <span className="text-white">upload -- .txt files</span>
              </div>

              <div
                onDrop={handleDrop}
                onDragOver={handleDragOver}
                onDragLeave={handleDragLeave}
                className={`border-2 ${isDragging ? 'border-white bg-white bg-opacity-10' : 'border-dashed border-gray-500'} p-12 text-center cursor-pointer transition-colors relative`}
              >
                <input
                  key={fileInputKey}
                  type="file"
                  multiple
                  accept=".txt"
                  onChange={handleFileInputChange}
                  className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
                  id="file-upload"
                />
                <label htmlFor="file-upload" className="cursor-pointer">
                  <FileIcon className="w-16 h-16 mx-auto mb-4 text-gray-500" />
                  <div className="text-gray-400 mb-2">
                    {'>'} Click to upload or drag and drop
                  </div>
                  <div className="text-gray-600 text-sm">
                    Multiple text files supported
                  </div>
                </label>
              </div>

              {selectedFiles.length > 0 && (
                <div className="mt-4 border border-gray-700 p-3">
                  <div className="text-sm text-gray-400 mb-2">Selected files:</div>
                  {selectedFiles.map((file) => (
                    <div key={file.name} className="text-sm text-white flex items-center gap-2 mb-1">
                      <span>{'>'}</span>
                      <span>{file.name}</span>
                      <span className="text-gray-500">({formatSize(file.size)})</span>
                    </div>
                  ))}
                </div>
              )}

              {!!uploadAlerts.length && (
                <div className="mt-4 space-y-2">
                  {uploadAlerts.map((alert) => (
                    <div
                      key={alert.id}
                      className="border rounded-md px-3 py-2 text-sm"
                      style={{
                        borderColor:
                          alert.tone === "success"
                            ? "#4ade80"
                            : alert.tone === "error"
                              ? "#f87171"
                              : "#60a5fa",
                        backgroundColor:
                          alert.tone === "success"
                            ? "rgba(74, 222, 128, 0.1)"
                            : alert.tone === "error"
                              ? "rgba(248, 113, 113, 0.1)"
                              : "rgba(96,165,250,0.12)",
                      }}
                    >
                      {alert.text}
                    </div>
                  ))}
                </div>
              )}

              <div className="mt-6">
                <Button
                  onClick={uploadFiles}
                  disabled={uploading || selectedFiles.length === 0}
                  className="bg-white text-black hover:bg-gray-200 border-2 border-white disabled:bg-gray-800 disabled:text-gray-600 disabled:border-gray-700"
                >
                  {uploading ? "Uploading…" : "Upload Files"}
                </Button>
              </div>

              {uploadAlerts.some(alert => alert.tone === "success") && (
                <div className="mt-4 border border-white bg-white bg-opacity-10 p-3 flex items-center gap-2">
                  <CheckCircle2 className="w-5 h-5" />
                  <span>Successfully uploaded {selectedFiles.length} file(s)!</span>
                </div>
              )}
            </TabsContent>

            <TabsContent value="files" className="p-6 mt-0">
              <FilesTabContent
                files={sortedFiles}
                loading={loadingFiles}
                onRefresh={loadFiles}
                showHashes={showHashes}
                onToggleHashes={() => setShowHashes(!showHashes)}
                onDownload={downloadFile}
                onDelete={deleteFile}
              />
            </TabsContent>
          </Tabs>

          <div className="border-t border-white px-4 py-3 text-center text-sm text-gray-400">
            Checkuvity by arjun selvam
          </div>
        </div>
      </div>

      {toast && (
        <Toast message={toast.message} tone={toast.tone} />
      )}

      {versionModal && (
        <VersionHistoryModal
          fileName={versionModal.fileName}
          versions={versionModal.versions}
          revertingVersionId={revertingVersionId}
          onClose={() => setVersionModal(null)}
          onRevert={(versionId) => revertVersion(versionModal.fileId, versionId)}
        />
      )}
    </div>
  );
}

interface HashValueCellProps {
  value?: string | null;
  placeholder: string;
  isVisible: boolean;
  onToggle: () => void;
  onCopy: () => void;
}

function HashValueCell({
  value,
  placeholder,
  isVisible,
  onToggle,
  onCopy,
}: HashValueCellProps) {
  if (!value) {
    return <span className="text-gray-500 italic">{placeholder}</span>;
  }

  return (
    <div className="flex items-center gap-2 min-w-0 max-w-full">
      <div className="font-mono text-xs break-words text-white flex-1 min-w-0 overflow-hidden">
        <span className="block truncate">
          {isVisible ? value : maskedValue(value)}
        </span>
      </div>
      <div className="flex items-center gap-1 flex-shrink-0">
        <Button
          type="button"
          variant="ghost"
          size="sm"
          className={ICON_BUTTON_CLASSES}
          aria-label={isVisible ? "Hide value" : "Show value"}
          onClick={onToggle}
        >
          {isVisible ? <EyeOff className={ICON_SIZE_CLASSES} /> : <Eye className={ICON_SIZE_CLASSES} />}
        </Button>
        <Button
          type="button"
          variant="ghost"
          size="sm"
          className={ICON_BUTTON_CLASSES}
          aria-label="Copy value"
          onClick={onCopy}
        >
          <Copy className={ICON_SIZE_CLASSES} />
        </Button>
      </div>
    </div>
  );
}

interface SignatureCellProps {
  fileName: string;
  value?: string | null;
  isVisible: boolean;
  onToggle: () => void;
  onCopy: () => void;
  isEditing: boolean;
  editingValue: string;
  onStartEdit: () => void;
  onChangeEdit: (value: string) => void;
  onCancelEdit: () => void;
  onSaveEdit: () => void;
  saving: boolean;
  onGenerate: () => void;
  generating: boolean;
}

function SignatureCell({
  fileName,
  value,
  isVisible,
  onToggle,
  onCopy,
  isEditing,
  editingValue,
  onStartEdit,
  onChangeEdit,
  onCancelEdit,
  onSaveEdit,
  saving,
  onGenerate,
  generating,
}: SignatureCellProps) {
  if (isEditing) {
    return (
      <div className="space-y-3">
        <input
          value={editingValue}
          onChange={(event) => onChangeEdit(event.target.value)}
          className="w-full border border-gray-600 rounded-md px-3 py-2 bg-black text-white font-mono text-sm"
          placeholder="64-character hexadecimal signature"
          autoFocus
          onKeyDown={(event) => {
            if (event.key === "Enter") {
              event.preventDefault();
              onSaveEdit();
            }
            if (event.key === "Escape") {
              event.preventDefault();
              onCancelEdit();
            }
          }}
        />
        <div className="flex items-center gap-2">
          <Button
            type="button"
            size="sm"
            disabled={saving}
            onClick={onSaveEdit}
          >
            {saving ? "Saving…" : "Save"}
          </Button>
          <Button
            type="button"
            size="sm"
            variant="ghost"
            onClick={onCancelEdit}
            disabled={saving}
          >
            Cancel
          </Button>
        </div>
      </div>
    );
  }

  if (!value) {
    return (
      <div className="space-y-2">
        <span className="text-gray-500 italic">Not set (click Generate)</span>
        <Button
          type="button"
          variant="secondary"
          size="sm"
          onClick={onGenerate}
          disabled={generating}
        >
          <Wand2 className="w-4 h-4" />
          {generating ? "Generating…" : "Generate sample"}
        </Button>
        <Button
          type="button"
          variant="ghost"
          size="sm"
          onClick={onStartEdit}
          disabled={generating}
        >
          Edit manually
        </Button>
      </div>
    );
  }

  return (
    <div className="flex items-center gap-2 min-w-0 max-w-full">
      <button
        type="button"
        className="text-left text-white font-mono text-xs break-words border border-transparent rounded-md px-2 py-1 hover:border-gray-600 transition-colors flex-1 min-w-0 overflow-hidden"
        title={`Edit signature for ${fileName}`}
        onClick={onStartEdit}
      >
        <span className="block truncate">
          {isVisible ? value : maskedValue(value)}
        </span>
      </button>
      <div className="flex items-center gap-1 flex-shrink-0">
        <Button
          type="button"
          variant="ghost"
          size="sm"
          className={ICON_BUTTON_CLASSES}
          aria-label={isVisible ? "Hide signature" : "Show signature"}
          onClick={onToggle}
        >
          {isVisible ? <EyeOff className={ICON_SIZE_CLASSES} /> : <Eye className={ICON_SIZE_CLASSES} />}
        </Button>
        <Button
          type="button"
          variant="ghost"
          size="sm"
          className={ICON_BUTTON_CLASSES}
          aria-label="Copy signature"
          onClick={onCopy}
        >
          <Copy className={ICON_SIZE_CLASSES} />
        </Button>
      </div>
    </div>
  );
}

// Constants
const TABLE_COLUMN_CLASSES = {
  header: "px-4 py-3 border-b border-gray-700",
  cell: "px-4 py-3",
  cellTop: "px-4 py-3 align-top",
  cellMiddle: "px-4 py-3 align-middle",
} as const;

const ICON_BUTTON_CLASSES = "h-6 w-6 p-0";
const ICON_SIZE_CLASSES = "w-3.5 h-3.5";

// Files Tab Component Props
interface FilesTabContentProps {
  files: FileRecord[];
  loading: boolean;
  onRefresh: () => Promise<void>;
  showHashes: boolean;
  onToggleHashes: () => void;
  onDownload: (file: FileRecord) => void;
  onDelete: (file: FileRecord) => void;
}

// Files Tab Content Component
function FilesTabContent({
  files,
  loading,
  onRefresh,
  showHashes,
  onToggleHashes,
  onDownload,
  onDelete,
}: FilesTabContentProps) {
  const handleRefresh = useCallback(() => {
    onRefresh().catch(console.error);
  }, [onRefresh]);

  const maskHash = (hash: string) => {
    if (showHashes) return hash;
    return '•'.repeat(64);
  };

  return (
    <>
      <FilesTabHeader
        fileCount={files.length}
        loading={loading}
        onRefresh={handleRefresh}
      />

      {loading ? (
        <FilesTabLoadingState />
      ) : files.length === 0 ? (
        <FilesTabEmptyState />
      ) : (
        <>
          {/* Action Bar */}
          <div className="flex justify-between items-center mb-4">
            <Button
              onClick={onToggleHashes}
              className="bg-black text-white hover:bg-gray-900 border border-white"
            >
              {showHashes ? (
                <>
                  <EyeOff className="w-4 h-4 mr-2" />
                  Hide Hashes
                </>
              ) : (
                <>
                  <Eye className="w-4 h-4 mr-2" />
                  Show Hashes
                </>
              )}
            </Button>
            <Button
              onClick={handleRefresh}
              className="bg-black text-white hover:bg-gray-900 border border-white"
            >
              <RefreshCcw className="w-4 h-4 mr-2" />
              Refresh
            </Button>
          </div>

          <FilesTable
            files={files}
            showHashes={showHashes}
            maskHash={maskHash}
            onDownload={onDownload}
            onDelete={onDelete}
          />
        </>
      )}
    </>
  );
}

// Files Tab Header Component
interface FilesTabHeaderProps {
  fileCount: number;
  loading: boolean;
  onRefresh: () => void;
}

function FilesTabHeader({ fileCount, loading, onRefresh }: FilesTabHeaderProps) {
  return (
    <div className="mb-6">
      <div className="mb-2">
        <span className="text-white">$ </span>
        <span className="text-white">ls -la</span>
      </div>
      <div className="text-gray-400 mb-4">
        Uploaded Files
      </div>
    </div>
  );
}

// Files Tab Loading State
function FilesTabLoadingState() {
  return (
    <div className="text-gray-400 text-center py-8">
      Loading files…
    </div>
  );
}

// Files Tab Empty State
function FilesTabEmptyState() {
  return (
    <div className="text-gray-400 text-center py-8">
      No files to display. Upload files from the Home tab.
    </div>
  );
}

// Files Table Component
interface FilesTableProps {
  files: FileRecord[];
  showHashes: boolean;
  maskHash: (hash: string) => string;
  onDownload: (file: FileRecord) => void;
  onDelete: (file: FileRecord) => void;
}

function FilesTable({
  files,
  showHashes,
  maskHash,
  onDownload,
  onDelete,
}: FilesTableProps) {
  return (
    <div className="border border-white overflow-hidden">
      <table className="w-full table-fixed border-collapse">
        <colgroup>
          <col className="w-[18%]" />
          <col className="w-[24%]" />
          <col className="w-[24%]" />
          <col className="w-[24%]" />
          <col className="w-[10%]" />
        </colgroup>
        <FilesTableHeader />
        <tbody>
          {files.map((file) => (
            <FilesTableRow
              key={file.id}
              file={file}
              showHashes={showHashes}
              maskHash={maskHash}
              onDownload={onDownload}
              onDelete={onDelete}
            />
          ))}
        </tbody>
      </table>
    </div>
  );
}

// Files Table Header Component
function FilesTableHeader() {
  return (
    <thead>
      <tr className="border-b border-white bg-white text-black text-xs">
        <th className="px-4 py-2 text-left uppercase tracking-wider">File Name</th>
        <th className="px-4 py-2 text-left uppercase tracking-wider">Original Hash</th>
        <th className="px-4 py-2 text-left uppercase tracking-wider">Signature</th>
        <th className="px-4 py-2 text-left uppercase tracking-wider">Post-Signature Hash</th>
        <th className="px-4 py-2 text-left uppercase tracking-wider">Actions</th>
      </tr>
    </thead>
  );
}

// Files Table Row Component
interface FilesTableRowProps {
  file: FileRecord;
  showHashes: boolean;
  maskHash: (hash: string) => string;
  onDownload: (file: FileRecord) => void;
  onDelete: (file: FileRecord) => void;
}

function FilesTableRow({
  file,
  showHashes,
  maskHash,
  onDownload,
  onDelete,
}: FilesTableRowProps) {
  const wrapStyles = { overflowWrap: "anywhere" as const, wordBreak: "break-word" as const };

  return (
    <tr className="border-b border-gray-700">
      <td className="px-4 py-3 align-top">
        <div className="text-xs text-white font-medium whitespace-pre-wrap" style={wrapStyles}>
          {file.file_name}
        </div>
        <div className="text-[11px] text-gray-500 mt-1">
          {formatSize(file.file_size)} • Updated {formatDate(file.updated_at)}
        </div>
      </td>
      <td className="px-4 py-3 align-top">
        <div
          className="text-[11px] text-gray-400 font-mono whitespace-pre-wrap"
          style={wrapStyles}
        >
          {file.original_hash ? maskHash(file.original_hash) : "N/A"}
        </div>
      </td>
      <td className="px-4 py-3 align-top">
        <div
          className="text-[11px] text-gray-400 font-mono whitespace-pre-wrap"
          style={wrapStyles}
        >
          {file.signature ? maskHash(file.signature) : "N/A"}
        </div>
      </td>
      <td className="px-4 py-3 align-top">
        <div
          className="text-[11px] text-gray-400 font-mono whitespace-pre-wrap"
          style={wrapStyles}
        >
          {file.post_signature_hash ? maskHash(file.post_signature_hash) : "N/A"}
        </div>
      </td>
      <td className="px-4 py-3 align-top">
        <FileActionsCell
          file={file}
          onDownload={onDownload}
          onDelete={onDelete}
        />
      </td>
    </tr>
  );
}

// File Name Cell Component
interface FileNameCellProps {
  file: FileRecord;
}

function FileNameCell({ file }: FileNameCellProps) {
  return (
    <div className="space-y-1">
      <div className="font-medium text-white">{file.file_name}</div>
      <div className="text-gray-500 text-xs">
        {formatSize(file.file_size)} • Updated {formatDate(file.updated_at)}
      </div>
    </div>
  );
}

// File Actions Cell Component
interface FileActionsCellProps {
  file: FileRecord;
  onDownload: (file: FileRecord) => void;
  onDelete: (file: FileRecord) => void;
}

function FileActionsCell({ file, onDownload, onDelete }: FileActionsCellProps) {
  return (
    <div className="flex flex-col gap-2 min-w-[120px]">
      <Button
        size="sm"
        type="button"
        onClick={() => onDownload(file)}
        className="bg-white text-black hover:bg-gray-200 border border-white"
      >
        <Download className="w-3 h-3 mr-1" />
        Download
      </Button>
      <Button
        size="sm"
        type="button"
        onClick={() => onDelete(file)}
        className="bg-black text-white hover:bg-gray-900 border border-white"
      >
        <Trash2 className="w-3 h-3 mr-1" />
        Delete
      </Button>
    </div>
  );
}

interface VersionHistoryModalProps {
  fileName: string;
  versions: FileVersion[];
  revertingVersionId: string | null;
  onClose: () => void;
  onRevert: (versionId: string) => void;
}

function VersionHistoryModal({
  fileName,
  versions,
  revertingVersionId,
  onClose,
  onRevert,
}: VersionHistoryModalProps) {
  const sortedVersions = useMemo(
    () =>
      [...versions].sort(
        (a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime(),
      ),
    [versions],
  );

  return (
    <div
      className="fixed inset-0 bg-black bg-opacity-60 flex items-center justify-center z-50 px-4"
      onClick={(event) => {
        if (event.target === event.currentTarget) {
          onClose();
        }
      }}
    >
      <div className="bg-black border border-gray-700 rounded-xl w-full max-w-4xl max-h-[80vh] overflow-hidden">
        <div className="flex items-center justify-between px-4 py-3 border-b border-gray-700 text-white">
          <div>
            <div className="uppercase text-xs tracking-wider text-gray-400">
              Version history
            </div>
            <div className="text-lg font-semibold">{fileName}</div>
          </div>
          <Button variant="ghost" onClick={onClose}>
            Close
          </Button>
        </div>
        <div className="overflow-y-auto">
          <table className="w-full text-left text-sm text-white">
            <thead className="bg-white text-black uppercase text-xs tracking-wider">
              <tr>
                <th className="px-4 py-3">Version</th>
                <th className="px-4 py-3">Signature</th>
                <th className="px-4 py-3">Post Hash</th>
                <th className="px-4 py-3">Timestamp</th>
                <th className="px-4 py-3">Reason</th>
                <th className="px-4 py-3 text-center">Action</th>
              </tr>
            </thead>
            <tbody>
              {sortedVersions.map((version, index) => {
                const isCurrent = index === 0;
                return (
                  <tr
                    key={version.id}
                    className="border-t border-gray-800 hover:bg-white hover:bg-opacity-5 transition-colors"
                  >
                    <td className="px-4 py-3">#{sortedVersions.length - index}</td>
                    <td className="px-4 py-3 font-mono text-xs break-all">
                      {version.signature ? truncate(version.signature) : "N/A"}
                    </td>
                    <td className="px-4 py-3 font-mono text-xs break-all">
                      {version.post_signature_hash
                        ? truncate(version.post_signature_hash)
                        : "N/A"}
                    </td>
                    <td className="px-4 py-3">{formatDate(version.created_at)}</td>
                    <td className="px-4 py-3">
                      {version.change_reason ?? "No reason provided"}
                    </td>
                    <td className="px-4 py-3 text-center">
                      {isCurrent ? (
                        <span className="text-green-400 font-medium">Current</span>
                      ) : (
                        <Button
                          type="button"
                          size="sm"
                          onClick={() => onRevert(version.id)}
                          disabled={revertingVersionId === version.id}
                        >
                          {revertingVersionId === version.id ? "Reverting…" : "Revert"}
                        </Button>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

interface ToastProps {
  message: string;
  tone: ToastTone;
}

function Toast({ message, tone }: ToastProps) {
  const background =
    tone === "success"
      ? "rgba(74,222,128,0.85)"
      : tone === "error"
        ? "rgba(248,113,113,0.85)"
        : "rgba(96,165,250,0.85)";

  const color = tone === "success" || tone === "info" ? "#030712" : "#ffffff";

  return (
    <div
      className="fixed top-6 right-6 px-4 py-3 rounded-lg shadow-lg text-sm font-medium z-50"
      style={{ backgroundColor: background, color }}
    >
      {message}
    </div>
  );
}
