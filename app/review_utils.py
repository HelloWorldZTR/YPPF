from rest_framework import serializers
from rest_framework.pagination import PageNumberPagination
from django.core.exceptions import ValidationError as DjangoValidationError
from .models import CourseReview, ReviewCategories, User

class CourseReviewSerializer(serializers.ModelSerializer):
    """
    DRF Serializer for CourseReview model to handle form data from postReview.html
    """
    
    class Meta:
        model = CourseReview
        fields = [
            'course', 'teacher', 'title', 'text', 
            'rating_recommend', 'rating_content', 'rating_workload', 'rating_grade',
            'anonymous_flag'
        ]
    
    # Override course field to validate against ReviewCategories
    course = serializers.PrimaryKeyRelatedField(
        queryset=ReviewCategories.objects.all(),
        error_messages={
            'required': '请选择课程',
            'does_not_exist': '所选课程不存在'
        }
    )
    
    teacher = serializers.CharField(
        max_length=48,
        required=False,
        allow_blank=True,
        help_text='授课教师姓名（可选）'
    )
    
    title = serializers.CharField(
        max_length=100,
        error_messages={
            'required': '请输入测评标题',
            'blank': '测评标题不能为空',
            'max_length': '测评标题不能超过100个字符'
        }
    )
    
    text = serializers.CharField(
        style={'base_template': 'textarea.html'},
        error_messages={
            'required': '请输入详细评价',
            'blank': '详细评价不能为空'
        }
    )
    
    rating_recommend = serializers.ChoiceField(
        choices=CourseReview.Rating.choices,
        default=CourseReview.Rating.FIVE,
        error_messages={
            'invalid_choice': '总体评价必须在1-5之间'
        }
    )
    
    rating_content = serializers.ChoiceField(
        choices=CourseReview.Rating.choices,
        default=CourseReview.Rating.FIVE,
        error_messages={
            'invalid_choice': '内容质量评分必须在1-5之间'
        }
    )
    
    rating_workload = serializers.ChoiceField(
        choices=CourseReview.Rating.choices,
        default=CourseReview.Rating.FIVE,
        error_messages={
            'invalid_choice': '工作量评分必须在1-5之间'
        }
    )
    
    rating_grade = serializers.ChoiceField(
        choices=CourseReview.Rating.choices,
        default=CourseReview.Rating.FIVE,
        error_messages={
            'invalid_choice': '考核评分必须在1-5之间'
        }
    )
    
    anonymous_flag = serializers.BooleanField(
        default=False,
        required=False
    )
    
    def validate_title(self, value):
        """Validate title field"""
        if not value or not value.strip():
            raise serializers.ValidationError('测评标题不能为空')
        return value.strip()
    
    def validate_text(self, value):
        """Validate text field"""
        if not value or not value.strip():
            raise serializers.ValidationError('详细评价不能为空')
        if len(value.strip()) < 10:
            raise serializers.ValidationError('详细评价至少需要10个字符')
        return value.strip()
    
    def validate_rating_recommend(self, value):
        """Validate rating_recommend field"""
        try:
            rating_int = int(value)
            if rating_int not in [1, 2, 3, 4, 5]:
                raise serializers.ValidationError('评分必须在1-5之间')
            return rating_int
        except (ValueError, TypeError):
            raise serializers.ValidationError('评分格式错误')
    
    def validate_rating_content(self, value):
        """Validate rating_content field"""
        try:
            rating_int = int(value)
            if rating_int not in [1, 2, 3, 4, 5]:
                raise serializers.ValidationError('评分必须在1-5之间')
            return rating_int
        except (ValueError, TypeError):
            raise serializers.ValidationError('评分格式错误')
    
    def validate_rating_workload(self, value):
        """Validate rating_workload field"""
        try:
            rating_int = int(value)
            if rating_int not in [1, 2, 3, 4, 5]:
                raise serializers.ValidationError('评分必须在1-5之间')
            return rating_int
        except (ValueError, TypeError):
            raise serializers.ValidationError('评分格式错误')
    
    def validate_rating_grade(self, value):
        """Validate rating_grade field"""
        try:
            rating_int = int(value)
            if rating_int not in [1, 2, 3, 4, 5]:
                raise serializers.ValidationError('评分必须在1-5之间')
            return rating_int
        except (ValueError, TypeError):
            raise serializers.ValidationError('评分格式错误')
    
    def create(self, validated_data):
        """
        Create a new CourseReview instance
        
        Args:
            validated_data (dict): Validated data from serializer
            
        Returns:
            CourseReview: The created review instance
        """
        # Extract reviewer from context
        request = self.context.get('request')
        if request and hasattr(request, 'user'):
            validated_data['reviewer'] = request.user
        
        return super().create(validated_data)

class ReviewCategoriesSerializer(serializers.ModelSerializer):
    """
    Serializer for ReviewCategories to provide course data for frontend
    """
    
    class Meta:
        model = ReviewCategories
        fields = ['id', 'course_name', 'course_type']
    
    def to_representation(self, instance):
        """
        Convert the model instance to a dictionary for frontend consumption
        """
        return {
            'id': instance.id,
            'name': instance.course_name,
            'category': instance.get_course_type_display()
        }

def get_course_data_for_frontend():
    """
    Get course data formatted for frontend consumption using DRF serializer
    
    Returns:
        list: List of dictionaries with course data
    """
    courses = ReviewCategories.objects.all().order_by('course_name')
    serializer = ReviewCategoriesSerializer(courses, many=True)
    return serializer.data

class CourseReviewListSerializer(serializers.ModelSerializer):
    reviewer = serializers.SerializerMethodField()
    semester = serializers.SerializerMethodField()
    time = serializers.SerializerMethodField()

    class Meta:
        model = CourseReview
        fields = [
            'reviewer', 'title', 'text', 'rating_recommend', 
            'rating_content', 'rating_workload', 'rating_grade',
            'time', 'semester', 'teacher', 'likes', 'dislikes'
        ]

    def get_reviewer(self, obj):
        return obj.reviewer.get_username() if not obj.anonymous_flag else "匿名用户"

    def get_semester(self, obj):
        semester_num = 1 if obj.semester == 'Spring' else 2
        return f"{obj.school_year}-{obj.school_year + 1}-{semester_num}"

    def get_time(self, obj):
        return obj.time.strftime("%Y-%m-%d")

class CourseReviewPagination(PageNumberPagination):
    page_size = 5
    page_size_query_param = 'page_size'
    max_page_size = 20

class CourseRatingSerializer(serializers.Serializer):
    recommend = serializers.FloatField()
    content = serializers.FloatField()
    workload = serializers.FloatField()
    grade = serializers.FloatField()

class SemesterRatingSerializer(serializers.Serializer):
    name = serializers.CharField()
    recommend = serializers.FloatField()
    content = serializers.FloatField()
    workload = serializers.FloatField()
    grade = serializers.FloatField()

class CourseInfoSerializer(serializers.Serializer):
    overall = CourseRatingSerializer()
    semesters = SemesterRatingSerializer(many=True)
    total_pages = serializers.IntegerField()
