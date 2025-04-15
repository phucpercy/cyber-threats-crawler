from functools import partial

import aws_cdk as cdk
from aws_cdk.pipelines import CodePipeline, CodePipelineSource, ShellStep, ManualApprovalStep
from constructs import Construct

from threats_crawler.pipeline_app_stage import PipelineAppStage


class ThreatCrawlerPipelineStack(cdk.Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        code_source = CodePipelineSource.git_hub(
            'phucpercy/cyber-threats-crawler',
            'main',
            authentication=cdk.SecretValue.secrets_manager('my-github-token')
        )
        ShellStepWithEnvs = partial(ShellStep)
        synth_step = ShellStepWithEnvs("Synth",
            input=code_source,
            install_commands=["npm install -g aws-cdk",
                "python -m pip install -r requirements.txt"],
            commands=["cdk synth"]
        )
        pipeline = CodePipeline(self, "Pipeline",
            pipeline_name="ThreatCrawlerPipeline",
            synth=synth_step
        )
        gamma_stage = pipeline.add_stage(PipelineAppStage(self, "Gamma"))
        gamma_stage.add_pre(ShellStepWithEnvs(
            "Unit Test",
            input=code_source,
            install_commands=["python -m pip install -r requirements.txt"],
            commands=["python -m pytest tests/unit"]
        ))
        prod_stage = pipeline.add_stage(PipelineAppStage(self, "Prod"))
        prod_stage.add_pre(ManualApprovalStep("Manual approval to deploy production"))
