
import React, { useState, useEffect } from 'react';
import { 
  PieChart, Pie, Cell, ResponsiveContainer, Tooltip, Legend 
} from 'recharts';
import { Card } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Separator } from '@/components/ui/separator';
import { Button } from '@/components/ui/button';
import { Download, PieChart as PieChartIcon, List } from 'lucide-react';

interface EmailProvider {
  name: string;
  value: number;
  color: string;
}

interface AnalysisResultsProps {
  results: {
    providers: EmailProvider[];
    totalEmails: number;
    validEmails: number;
    invalidEmails: number;
    raw: Record<string, string[]>;
  };
}

const COLORS = [
  '#0088FE', '#00C49F', '#FFBB28', '#FF8042', '#A569BD', 
  '#5DADE2', '#45B39D', '#F5B041', '#EC7063', '#AF7AC5',
];

const AnalysisResults = ({ results }: AnalysisResultsProps) => {
  const [activeTab, setActiveTab] = useState('chart');
  const [animation, setAnimation] = useState(false);

  // Trigger animation when component mounts
  useEffect(() => {
    setAnimation(true);
  }, []);

  const handleDownloadCSV = () => {
    // Create CSV content
    let csvContent = "Provider,Email\n";
    
    Object.entries(results.raw).forEach(([provider, emails]) => {
      emails.forEach(email => {
        csvContent += `${provider},"${email}"\n`;
      });
    });
    
    // Create and trigger download
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.setAttribute('href', url);
    link.setAttribute('download', 'email_analysis.csv');
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  return (
    <div className={`w-full max-w-3xl mx-auto transition-opacity duration-700 ${animation ? 'opacity-100' : 'opacity-0'}`}>
      <Card className="p-6 shadow-sm border border-slate-200">
        <div className="mb-4 flex justify-between items-center">
          <div>
            <span className="text-xs bg-primary/10 text-primary px-2 py-1 rounded-full font-medium">Analysis Complete</span>
            <h2 className="text-2xl font-semibold mt-2">Email Provider Analysis</h2>
            <p className="text-muted-foreground">
              Analyzed {results.totalEmails} emails • {results.validEmails} valid • {results.invalidEmails} invalid
            </p>
          </div>
          <Button 
            variant="outline" 
            size="sm" 
            className="flex items-center gap-1"
            onClick={handleDownloadCSV}
          >
            <Download className="h-4 w-4" />
            <span>Export</span>
          </Button>
        </div>
        
        <Separator className="my-4" />
        
        <Tabs defaultValue="chart" value={activeTab} onValueChange={setActiveTab} className="mt-6">
          <TabsList className="mb-4">
            <TabsTrigger value="chart" className="flex items-center gap-1">
              <PieChartIcon className="h-4 w-4" />
              <span>Chart View</span>
            </TabsTrigger>
            <TabsTrigger value="list" className="flex items-center gap-1">
              <List className="h-4 w-4" />
              <span>List View</span>
            </TabsTrigger>
          </TabsList>
          
          <TabsContent value="chart" className="pt-2">
            <div className="h-80">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={results.providers}
                    cx="50%"
                    cy="50%"
                    labelLine={false}
                    outerRadius={100}
                    fill="#8884d8"
                    dataKey="value"
                    animationDuration={1500}
                    label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                  >
                    {results.providers.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color || COLORS[index % COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip />
                  <Legend />
                </PieChart>
              </ResponsiveContainer>
            </div>
          </TabsContent>
          
          <TabsContent value="list" className="pt-2 animate-fade-in">
            <div className="grid gap-3">
              {results.providers.map((provider, index) => (
                <div 
                  key={provider.name}
                  className="flex items-center justify-between p-3 rounded-lg bg-secondary/50 border border-border"
                >
                  <div className="flex items-center gap-3">
                    <div 
                      className="w-4 h-4 rounded-full" 
                      style={{ backgroundColor: provider.color || COLORS[index % COLORS.length] }}
                    />
                    <span className="font-medium">{provider.name}</span>
                  </div>
                  <div className="flex items-center gap-3">
                    <span className="px-2 py-1 bg-background rounded-md text-sm">
                      {provider.value} emails
                    </span>
                    <span className="text-muted-foreground text-sm">
                      {((provider.value / results.validEmails) * 100).toFixed(1)}%
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </TabsContent>
        </Tabs>
      </Card>
    </div>
  );
};

export default AnalysisResults;
