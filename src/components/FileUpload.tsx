
import React, { useRef, useState } from 'react';
import { Button } from '@/components/ui/button';
import { UploadCloud } from 'lucide-react';
import { toast } from '@/components/ui/use-toast';

interface FileUploadProps {
  onFileUpload: (file: File) => void;
  isProcessing: boolean;
}

const FileUpload = ({ onFileUpload, isProcessing }: FileUploadProps) => {
  const [isDragging, setIsDragging] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleDragEnter = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(true);
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);

    const files = e.dataTransfer.files;
    if (files.length) {
      validateAndProcessFile(files[0]);
    }
  };

  const handleFileInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (files && files.length) {
      validateAndProcessFile(files[0]);
    }
  };

  const validateAndProcessFile = (file: File) => {
    // Check if file is CSV
    if (file.type !== 'text/csv' && !file.name.endsWith('.csv')) {
      toast({
        title: "Invalid file format",
        description: "Please upload a CSV file.",
        variant: "destructive"
      });
      return;
    }

    // Check file size (max 5MB)
    if (file.size > 5 * 1024 * 1024) {
      toast({
        title: "File too large",
        description: "File size should be less than 5MB.",
        variant: "destructive"
      });
      return;
    }

    onFileUpload(file);
  };

  const handleButtonClick = () => {
    if (fileInputRef.current) {
      fileInputRef.current.click();
    }
  };

  return (
    <div
      className={`
        w-full max-w-md mx-auto p-8 rounded-xl transition-all duration-300 
        ${isDragging ? 'glassmorphism scale-105' : 'border-2 border-dashed border-gray-300 hover:border-primary'}
      `}
      onDragEnter={handleDragEnter}
      onDragLeave={handleDragLeave}
      onDragOver={handleDragOver}
      onDrop={handleDrop}
    >
      <div className="flex flex-col items-center justify-center text-center">
        <UploadCloud className="w-16 h-16 text-primary mb-4 opacity-90" />
        <h3 className="text-lg font-medium mb-2">Upload CSV File</h3>
        <p className="text-muted-foreground mb-4 text-sm">
          Drag and drop your CSV file here, or click to browse
        </p>
        <input
          type="file"
          ref={fileInputRef}
          onChange={handleFileInputChange}
          accept=".csv"
          className="hidden"
          disabled={isProcessing}
        />
        <Button 
          onClick={handleButtonClick} 
          disabled={isProcessing}
          className="transition-all duration-300 hover:scale-105"
        >
          {isProcessing ? 'Processing...' : 'Select File'}
        </Button>
        
        <p className="text-xs text-muted-foreground mt-4">
          Max file size: 5MB
        </p>
      </div>
    </div>
  );
};

export default FileUpload;
