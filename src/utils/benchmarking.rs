use std::time::{Duration, Instant};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Represents the type of operation being performed
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OperationType {
    Synchronous,
    Asynchronous,
    Blocking,
}

impl std::fmt::Display for OperationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OperationType::Synchronous => write!(f, "SYNC"),
            OperationType::Asynchronous => write!(f, "ASYNC"),
            OperationType::Blocking => write!(f, "BLOCKING"),
        }
    }
}

/// An ongoing operation being tracked
#[derive(Debug)]
struct TrackedOperation {
    name: String,
    start_time: Instant,
    operation_type: OperationType,
    parent: Option<String>,
}

/// A completed operation with timing information
#[derive(Debug, Clone)]
pub struct TimingInfo {
    pub name: String,
    pub duration_ms: u64,
    pub operation_type: OperationType,
    pub parent: Option<String>,
    pub children: Vec<String>,
}

impl TimingInfo {
    fn new(name: String, duration: Duration, op_type: OperationType, parent: Option<String>) -> Self {
        Self {
            name,
            duration_ms: duration.as_millis() as u64,
            operation_type: op_type,
            parent,
            children: Vec::new(),
        }
    }
}

/// Global timer for tracking operation durations across the application
#[derive(Debug, Clone)]
pub struct OperationTimer {
    operations: Arc<Mutex<HashMap<String, TrackedOperation>>>,
    completed: Arc<Mutex<HashMap<String, TimingInfo>>>,
    operation_sequence: Arc<Mutex<Vec<String>>>,
}

impl Default for OperationTimer {
    fn default() -> Self {
        Self::new()
    }
}

impl OperationTimer {
    pub fn new() -> Self {
        Self {
            operations: Arc::new(Mutex::new(HashMap::new())),
            completed: Arc::new(Mutex::new(HashMap::new())),
            operation_sequence: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Start timing a new operation
    pub async fn start_operation(
        &self,
        operation_name: &str,
        operation_type: OperationType,
        parent: Option<&str>,
    ) {
        let mut operations = self.operations.lock().await;
        let parent_name = parent.map(|p| p.to_string());

        operations.insert(
            operation_name.to_string(),
            TrackedOperation {
                name: operation_name.to_string(),
                start_time: Instant::now(),
                operation_type,
                parent: parent_name,
            },
        );
    }

    /// End timing for an operation and record its metrics
    pub async fn end_operation(&self, operation_name: &str) {
        let now = Instant::now();
        let mut operations = self.operations.lock().await;
        let mut completed = self.completed.lock().await;
        let mut sequence = self.operation_sequence.lock().await;

        if let Some(operation) = operations.remove(operation_name) {
            let duration = now.duration_since(operation.start_time);
            let timing_info = TimingInfo::new(
                operation.name.clone(),
                duration,
                operation.operation_type,
                operation.parent.clone(),
            );

            // Add this operation to the sequence
            sequence.push(operation_name.to_string());

            // If this operation has a parent, add it as a child to the parent
            if let Some(parent_name) = &operation.parent {
                if let Some(parent_info) = completed.get_mut(parent_name) {
                    parent_info.children.push(operation_name.to_string());
                }
            }

            completed.insert(operation_name.to_string(), timing_info);
        }
    }

    /// Generate a report of all completed operations
    pub async fn generate_report(&self) -> String {
        let completed = self.completed.lock().await;
        let sequence = self.operation_sequence.lock().await;

        let mut report = String::new();
        // report.push_str("\n=== OPERATION TIMING REPORT ===\n");

        // // First, show operations in execution order
        // report.push_str("\nOperation Sequence:\n");
        // for (idx, op_name) in sequence.iter().enumerate() {
        //     if let Some(op) = completed.get(op_name) {
        //         report.push_str(&format!(
        //             "{}. [{}] {} - {} ms\n",
        //             idx + 1,
        //             op.operation_type,
        //             op.name,
        //             op.duration_ms
        //         ));
        //     }
        // }

        // // Then show a hierarchical view
        // report.push_str("\nOperation Hierarchy:\n");
        
        // // Get root operations (those without parents)
        // let root_operations: Vec<_> = completed
        //     .values()
        //     .filter(|op| op.parent.is_none())
        //     .collect();

        // // Recursively build the tree
        // for root in root_operations {
        //     self.build_hierarchy_report(&mut report, root, &completed, 0);
        // }

        // // Add total execution time
        // let total_time: u64 = completed.values().map(|op| op.duration_ms).sum();
        // report.push_str(&format!("\nTotal Execution Time: {} ms\n", total_time));

        report
    }

    fn build_hierarchy_report(
        &self,
        report: &mut String,
        operation: &TimingInfo,
        all_operations: &HashMap<String, TimingInfo>,
        depth: usize,
    ) {
        let indent = "  ".repeat(depth);
        report.push_str(&format!(
            "{}[{}] {} - {} ms\n",
            indent,
            operation.operation_type,
            operation.name,
            operation.duration_ms
        ));

        for child_name in &operation.children {
            if let Some(child) = all_operations.get(child_name) {
                self.build_hierarchy_report(report, child, all_operations, depth + 1);
            }
        }
    }
    
}

/// Convenience function for timing an operation with a guard
pub async fn time_operation<F, T>(
    timer: &OperationTimer,
    name: &str, 
    operation_type: OperationType,
    parent: Option<&str>,
    operation: F
) -> T 
where
    F: std::future::Future<Output = T>,
{
    timer.start_operation(name, operation_type, parent).await;
    let result = operation.await;
    timer.end_operation(name).await;
    result
} 